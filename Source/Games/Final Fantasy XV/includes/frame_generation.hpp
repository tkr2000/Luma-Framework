#pragma once

// Frame generation for FFXV, part 1: proxy swap chain presented through DX12 (port of the "SwapRedirect" prototype).
//
//  - The real dxgi.dll functions CDXGIFactory::CreateSwapChain / CreateSwapChainForHwnd are detoured (SafetyHook).
//    Their addresses are read from the pristine factory vtable in dxgi.dll on disk, so this works even if ReShade
//    already replaced the vtable entries. The call chain is: game -> ReShade's vtable hook -> real function -> us,
//    so ReShade and Luma wrap our proxy as if it was a real swap chain.
//  - The game's main window gets a "ProxySwapChain" (IDXGISwapChain4) that renders into a DX11 texture we own.
//  - On present, that texture is copied (through D3D12Interop) into a real DX12 swap chain created on the game window.
//    If DX12 can't be used, a plain DX11 flip model swap chain is used as fallback.
//
// Settings (ReShade.ini): [LUMA_FFXV_FRAME_GENERATION] Enabled=0/1, DebugSplit=0/1

#include <d3d11_4.h>
#include <d3d12.h>
#include <dxgi1_6.h>
#include <wrl/client.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <format>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include <safetyhook.hpp>

#include "../../../Core/interop/D3D12Interop.h"

namespace FrameGen
{
   using Microsoft::WRL::ComPtr;

   constexpr const char* config_section = "LUMA_FFXV_FRAME_GENERATION";
   constexpr UINT dx12_back_buffer_count = 3;
   // ReShade's interface ID to get the original object from its proxies (see ReShade's "com_utils.hpp")
   constexpr GUID IID_UnwrappedObject = {0x7f2c9a11, 0x3b4e, 0x4d6a, {0x81, 0x2f, 0x5e, 0x9c, 0xd3, 0x7a, 0x1b, 0x42}};

   void Log(reshade::log::level level, const std::string& message)
   {
      reshade::log::message(level, ("[FFXV FG] " + message).c_str());
   }

   struct Settings
   {
      bool enabled = true;
      bool debug_split = false; // Only the left half of the frame is copied, the right half is magenta: proves the DX12 path is on screen
   };
   Settings g_settings;

   // ------------------------------------------------------------------------------------------------
   // Hooks
   // ------------------------------------------------------------------------------------------------
   using PFN_CreateSwapChain = HRESULT(STDMETHODCALLTYPE*)(IDXGIFactory*, IUnknown*, DXGI_SWAP_CHAIN_DESC*, IDXGISwapChain**);
   using PFN_CreateSwapChainForHwnd = HRESULT(STDMETHODCALLTYPE*)(IDXGIFactory2*, IUnknown*, HWND, const DXGI_SWAP_CHAIN_DESC1*, const DXGI_SWAP_CHAIN_FULLSCREEN_DESC*, IDXGIOutput*, IDXGISwapChain1**);

   std::mutex g_hook_mutex;
   bool g_hooks_attempted = false;
   safetyhook::InlineHook g_create_swapchain_hook;
   safetyhook::InlineHook g_create_swapchain_for_hwnd_hook;
   PFN_CreateSwapChain g_real_CreateSwapChain = nullptr; // Trampolines (the original function bodies)
   PFN_CreateSwapChainForHwnd g_real_CreateSwapChainForHwnd = nullptr;
   thread_local int t_nested = 0; // > 0 while inside a real swap chain creation (DXGI might call its other entry point internally)

   class ProxySwapChain;
   std::atomic<ProxySwapChain*> g_active_proxy = nullptr; // Only one window is redirected

   // Calls a real swap chain creation without our interception (also bypasses any vtable hook, like ReShade's)
   HRESULT RealCreateSwapChainForHwnd(IDXGIFactory2* factory, IUnknown* device, HWND hwnd, const DXGI_SWAP_CHAIN_DESC1* desc, IDXGISwapChain1** swapchain)
   {
      t_nested++;
      const HRESULT hr = g_real_CreateSwapChainForHwnd(factory, device, hwnd, desc, nullptr, nullptr, swapchain);
      t_nested--;
      return hr;
   }

   HMODULE GetSystemDxgi()
   {
      wchar_t path[MAX_PATH] = {};
      const UINT length = GetSystemDirectoryW(path, MAX_PATH);
      if (length == 0 || length + 10 >= MAX_PATH)
         return nullptr;
      wcscat_s(path, L"\\dxgi.dll");
      return LoadLibraryW(path); // Never freed (it stays loaded anyway)
   }

   // Returns the original function of a vtable entry that lives inside "module", read from the module's file on disk
   // (x64 PE: the entry holds an absolute address relative to the preferred image base).
   void* GetPristineVtableEntry(HMODULE module, void** vtable, UINT index)
   {
      auto* const base = reinterpret_cast<const uint8_t*>(module);
      const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
      const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
      const uintptr_t slot = reinterpret_cast<uintptr_t>(&vtable[index]);
      if (slot < uintptr_t(base) || slot + sizeof(void*) > uintptr_t(base) + nt->OptionalHeader.SizeOfImage)
         return nullptr; // The vtable isn't in the module
      const uint32_t slot_rva = uint32_t(slot - uintptr_t(base));

      wchar_t path[MAX_PATH] = {};
      if (!GetModuleFileNameW(module, path, MAX_PATH))
         return nullptr;
      HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (file == INVALID_HANDLE_VALUE)
         return nullptr;
      std::vector<uint8_t> data;
      LARGE_INTEGER size = {};
      if (GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart < (64ll << 20))
      {
         data.resize(size_t(size.QuadPart));
         DWORD read = 0;
         if (!ReadFile(file, data.data(), DWORD(data.size()), &read, nullptr) || read != data.size())
            data.clear();
      }
      CloseHandle(file);
      if (data.size() < sizeof(IMAGE_DOS_HEADER))
         return nullptr;

      const auto* file_dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
      if (file_dos->e_magic != IMAGE_DOS_SIGNATURE || size_t(file_dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > data.size())
         return nullptr;
      const auto* file_nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(data.data() + file_dos->e_lfanew);
      if (file_nt->Signature != IMAGE_NT_SIGNATURE || file_nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
         return nullptr;
      const auto* sections = IMAGE_FIRST_SECTION(file_nt);
      const auto* sections_end = sections + file_nt->FileHeader.NumberOfSections;
      if (reinterpret_cast<const uint8_t*>(sections_end) > data.data() + data.size())
         return nullptr;

      uint64_t entry = 0;
      for (const auto* section = sections; section != sections_end; section++)
      {
         if (slot_rva >= section->VirtualAddress && slot_rva + sizeof(entry) <= section->VirtualAddress + section->SizeOfRawData)
         {
            const size_t offset = section->PointerToRawData + (slot_rva - section->VirtualAddress);
            if (offset + sizeof(entry) <= data.size())
               std::memcpy(&entry, data.data() + offset, sizeof(entry));
            break;
         }
      }
      if (entry <= file_nt->OptionalHeader.ImageBase)
         return nullptr;
      const uint64_t function_rva = entry - file_nt->OptionalHeader.ImageBase;
      // The function has to be in an executable section
      for (const auto* section = sections; section != sections_end; section++)
      {
         if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) && function_rva >= section->VirtualAddress && function_rva < uint64_t(section->VirtualAddress) + section->Misc.VirtualSize)
            return const_cast<uint8_t*>(base) + function_rva;
      }
      return nullptr;
   }

   HRESULT STDMETHODCALLTYPE Hook_CreateSwapChain(IDXGIFactory* factory, IUnknown* device, DXGI_SWAP_CHAIN_DESC* desc, IDXGISwapChain** swapchain);
   HRESULT STDMETHODCALLTYPE Hook_CreateSwapChainForHwnd(IDXGIFactory2* factory, IUnknown* device, HWND hwnd, const DXGI_SWAP_CHAIN_DESC1* desc, const DXGI_SWAP_CHAIN_FULLSCREEN_DESC* fullscreen_desc, IDXGIOutput* restrict_to_output, IDXGISwapChain1** swapchain);

   void InstallHooks()
   {
      std::scoped_lock lock(g_hook_mutex);
      if (g_hooks_attempted)
         return;
      g_hooks_attempted = true;

      reshade::get_config_value(nullptr, config_section, "Enabled", g_settings.enabled);
      reshade::get_config_value(nullptr, config_section, "DebugSplit", g_settings.debug_split);
      if (!g_settings.enabled)
      {
         Log(reshade::log::level::info, "Disabled in ReShade.ini, the game keeps its own swap chain");
         return;
      }

      HMODULE dxgi = GetSystemDxgi();
      using PFN_CreateDXGIFactory1 = HRESULT(WINAPI*)(REFIID, void**);
      const auto create_factory = dxgi ? reinterpret_cast<PFN_CreateDXGIFactory1>(GetProcAddress(dxgi, "CreateDXGIFactory1")) : nullptr;
      ComPtr<IDXGIFactory2> factory;
      if (!create_factory || FAILED(create_factory(IID_PPV_ARGS(&factory))))
      {
         Log(reshade::log::level::error, "Couldn't create a DXGI factory, nothing is redirected");
         return;
      }
      void** const vtable = *reinterpret_cast<void***>(factory.Get());
      void* const create_swapchain = GetPristineVtableEntry(dxgi, vtable, 10); // IDXGIFactory::CreateSwapChain
      void* const create_swapchain_for_hwnd = GetPristineVtableEntry(dxgi, vtable, 15); // IDXGIFactory2::CreateSwapChainForHwnd
      if (!create_swapchain || !create_swapchain_for_hwnd)
      {
         Log(reshade::log::level::error, "Couldn't find the DXGI swap chain creation functions, nothing is redirected");
         return;
      }
      if (vtable[10] != create_swapchain || vtable[15] != create_swapchain_for_hwnd)
         Log(reshade::log::level::info, "The DXGI factory vtable was already hooked (e.g. by ReShade), hooking the original functions below it");

      g_create_swapchain_hook = safetyhook::create_inline(create_swapchain, &Hook_CreateSwapChain);
      g_create_swapchain_for_hwnd_hook = safetyhook::create_inline(create_swapchain_for_hwnd, &Hook_CreateSwapChainForHwnd);
      if (!g_create_swapchain_hook || !g_create_swapchain_for_hwnd_hook)
      {
         Log(reshade::log::level::error, "Failed to hook the DXGI swap chain creation, nothing is redirected");
         g_create_swapchain_hook = {};
         g_create_swapchain_for_hwnd_hook = {};
         return;
      }
      g_real_CreateSwapChain = g_create_swapchain_hook.original<PFN_CreateSwapChain>();
      g_real_CreateSwapChainForHwnd = g_create_swapchain_for_hwnd_hook.original<PFN_CreateSwapChainForHwnd>();
      Log(reshade::log::level::info, std::format("Hooked the DXGI swap chain creation (debug split {})", g_settings.debug_split));
   }

   // ------------------------------------------------------------------------------------------------
   // Formats
   // ------------------------------------------------------------------------------------------------
   // The format we create the proxy back buffer with: typeless when the game might also use sRGB views on it (like on real swap chains)
   DXGI_FORMAT ToBackBufferFormat(DXGI_FORMAT format)
   {
      switch (format)
      {
      case DXGI_FORMAT_R8G8B8A8_UNORM:
      case DXGI_FORMAT_R8G8B8A8_UNORM_SRGB:
         return DXGI_FORMAT_R8G8B8A8_TYPELESS;
      case DXGI_FORMAT_B8G8R8A8_UNORM:
      case DXGI_FORMAT_B8G8R8A8_UNORM_SRGB:
         return DXGI_FORMAT_B8G8R8A8_TYPELESS;
      case DXGI_FORMAT_R16G16B16A16_FLOAT:
      case DXGI_FORMAT_R10G10B10A2_UNORM:
         return format;
      default:
         return DXGI_FORMAT_UNKNOWN;
      }
   }

   // The format of the real (flip model) swap chain
   DXGI_FORMAT ToPresentFormat(DXGI_FORMAT format)
   {
      switch (format)
      {
      case DXGI_FORMAT_R8G8B8A8_UNORM:
      case DXGI_FORMAT_R8G8B8A8_UNORM_SRGB:
      case DXGI_FORMAT_R8G8B8A8_TYPELESS:
         return DXGI_FORMAT_R8G8B8A8_UNORM;
      case DXGI_FORMAT_B8G8R8A8_UNORM:
      case DXGI_FORMAT_B8G8R8A8_UNORM_SRGB:
      case DXGI_FORMAT_B8G8R8A8_TYPELESS:
         return DXGI_FORMAT_B8G8R8A8_UNORM;
      case DXGI_FORMAT_R16G16B16A16_FLOAT:
      case DXGI_FORMAT_R10G10B10A2_UNORM:
         return format;
      default:
         return DXGI_FORMAT_UNKNOWN;
      }
   }

   DXGI_COLOR_SPACE_TYPE DefaultColorSpace(DXGI_FORMAT format)
   {
      return format == DXGI_FORMAT_R16G16B16A16_FLOAT ? DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709 : DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709;
   }

   bool IsFlipModel(DXGI_SWAP_EFFECT effect)
   {
      return effect == DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL || effect == DXGI_SWAP_EFFECT_FLIP_DISCARD;
   }

   struct GuidLess
   {
      bool operator()(const GUID& a, const GUID& b) const { return std::memcmp(&a, &b, sizeof(GUID)) < 0; }
   };

   // ------------------------------------------------------------------------------------------------
   // Proxy swap chain
   // ------------------------------------------------------------------------------------------------
   class ProxySwapChain final : public IDXGISwapChain4
   {
   public:
      static HRESULT Create(IDXGIFactory2* factory, IUnknown* device, HWND hwnd, const DXGI_SWAP_CHAIN_DESC1& desc, const DXGI_SWAP_CHAIN_FULLSCREEN_DESC* fullscreen_desc, IDXGISwapChain1** swapchain)
      {
         auto* proxy = new ProxySwapChain();
         const HRESULT hr = proxy->Init(factory, device, hwnd, desc, fullscreen_desc);
         if (FAILED(hr))
         {
            proxy->Release();
            return hr;
         }
         ProxySwapChain* expected = nullptr;
         if (!g_active_proxy.compare_exchange_strong(expected, proxy))
         {
            proxy->Release();
            return E_FAIL;
         }
         proxy->registered_ = true;
         *swapchain = proxy;
         Log(reshade::log::level::info, std::format("Intercepted the game's swap chain: {}x{} format {} buffers {} swap effect {} flags {:#x}", desc.Width, desc.Height, int(desc.Format), desc.BufferCount, int(desc.SwapEffect), desc.Flags));
         return S_OK;
      }

      // IUnknown
      HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** object) override
      {
         if (!object)
            return E_POINTER;
         if (riid == __uuidof(IUnknown) || riid == __uuidof(IDXGIObject) || riid == __uuidof(IDXGIDeviceSubObject) || riid == __uuidof(IDXGISwapChain)
            || riid == __uuidof(IDXGISwapChain1) || riid == __uuidof(IDXGISwapChain2) || riid == __uuidof(IDXGISwapChain3) || riid == __uuidof(IDXGISwapChain4))
         {
            AddRef();
            *object = static_cast<IDXGISwapChain4*>(this);
            return S_OK;
         }
         *object = nullptr;
         return E_NOINTERFACE;
      }
      ULONG STDMETHODCALLTYPE AddRef() override { return ++refs_; }
      ULONG STDMETHODCALLTYPE Release() override
      {
         const ULONG refs = --refs_;
         if (refs == 0)
            delete this;
         return refs;
      }

      // IDXGIObject
      HRESULT STDMETHODCALLTYPE SetPrivateData(REFGUID name, UINT size, const void* data) override
      {
         std::scoped_lock lock(mutex_);
         private_interfaces_.erase(name);
         if (!data)
            private_data_.erase(name);
         else
            private_data_[name].assign(static_cast<const uint8_t*>(data), static_cast<const uint8_t*>(data) + size);
         return S_OK;
      }
      HRESULT STDMETHODCALLTYPE SetPrivateDataInterface(REFGUID name, const IUnknown* unknown) override
      {
         std::scoped_lock lock(mutex_);
         private_data_.erase(name);
         if (!unknown)
            private_interfaces_.erase(name);
         else
            private_interfaces_[name] = const_cast<IUnknown*>(unknown);
         return S_OK;
      }
      HRESULT STDMETHODCALLTYPE GetPrivateData(REFGUID name, UINT* size, void* data) override
      {
         if (!size)
            return E_INVALIDARG;
         std::scoped_lock lock(mutex_);
         if (const auto it = private_interfaces_.find(name); it != private_interfaces_.end())
         {
            if (!data)
            {
               *size = sizeof(IUnknown*);
               return S_OK;
            }
            if (*size < sizeof(IUnknown*))
               return DXGI_ERROR_MORE_DATA;
            IUnknown* unknown = it->second.Get();
            unknown->AddRef();
            std::memcpy(data, &unknown, sizeof(unknown));
            *size = sizeof(IUnknown*);
            return S_OK;
         }
         const auto it = private_data_.find(name);
         if (it == private_data_.end())
         {
            *size = 0;
            return DXGI_ERROR_NOT_FOUND;
         }
         if (!data)
         {
            *size = UINT(it->second.size());
            return S_OK;
         }
         if (*size < it->second.size())
            return DXGI_ERROR_MORE_DATA;
         std::memcpy(data, it->second.data(), it->second.size());
         *size = UINT(it->second.size());
         return S_OK;
      }
      HRESULT STDMETHODCALLTYPE GetParent(REFIID riid, void** parent) override { return factory_->QueryInterface(riid, parent); }

      // IDXGIDeviceSubObject
      HRESULT STDMETHODCALLTYPE GetDevice(REFIID riid, void** device) override { return game_device_->QueryInterface(riid, device); }

      // IDXGISwapChain
      HRESULT STDMETHODCALLTYPE Present(UINT sync_interval, UINT flags) override { return PresentImpl(sync_interval, flags); }
      HRESULT STDMETHODCALLTYPE GetBuffer(UINT buffer, REFIID riid, void** surface) override
      {
         if (!surface)
            return E_POINTER;
         std::scoped_lock lock(mutex_);
         // DX11 swap chains only expose the current back buffer, whatever the index (one texture is enough as we copy it out on present)
         if (buffer >= std::max(desc_.BufferCount, 1u) || !back_buffer_)
            return DXGI_ERROR_INVALID_CALL;
         return back_buffer_->QueryInterface(riid, surface);
      }
      HRESULT STDMETHODCALLTYPE SetFullscreenState(BOOL fullscreen, IDXGIOutput* target) override
      {
         if (fullscreen)
         {
            Log(reshade::log::level::warning, "Exclusive fullscreen was requested and refused (use borderless)");
            return DXGI_ERROR_NOT_CURRENTLY_AVAILABLE;
         }
         return S_OK;
      }
      HRESULT STDMETHODCALLTYPE GetFullscreenState(BOOL* fullscreen, IDXGIOutput** target) override
      {
         if (fullscreen)
            *fullscreen = FALSE;
         if (target)
            *target = nullptr;
         return S_OK;
      }
      HRESULT STDMETHODCALLTYPE GetDesc(DXGI_SWAP_CHAIN_DESC* desc) override
      {
         if (!desc)
            return E_POINTER;
         std::scoped_lock lock(mutex_);
         *desc = {};
         desc->BufferDesc.Width = desc_.Width;
         desc->BufferDesc.Height = desc_.Height;
         desc->BufferDesc.RefreshRate = fullscreen_desc_.RefreshRate;
         desc->BufferDesc.Format = desc_.Format;
         desc->BufferDesc.ScanlineOrdering = fullscreen_desc_.ScanlineOrdering;
         desc->BufferDesc.Scaling = fullscreen_desc_.Scaling;
         desc->SampleDesc = desc_.SampleDesc;
         desc->BufferUsage = desc_.BufferUsage;
         desc->BufferCount = desc_.BufferCount;
         desc->OutputWindow = hwnd_;
         desc->Windowed = TRUE;
         desc->SwapEffect = desc_.SwapEffect;
         desc->Flags = desc_.Flags;
         return S_OK;
      }
      HRESULT STDMETHODCALLTYPE ResizeBuffers(UINT buffer_count, UINT width, UINT height, DXGI_FORMAT format, UINT flags) override
      {
         std::scoped_lock lock(mutex_);
         if (width == 0 || height == 0)
         {
            RECT client = {};
            GetClientRect(hwnd_, &client);
            if (width == 0)
               width = std::max<LONG>(client.right, 1);
            if (height == 0)
               height = std::max<LONG>(client.bottom, 1);
         }
         if (format == DXGI_FORMAT_UNKNOWN)
            format = desc_.Format;
         if (ToBackBufferFormat(format) == DXGI_FORMAT_UNKNOWN)
            return DXGI_ERROR_INVALID_CALL;
         // Like DXGI, refuse while the application still references the back buffer
         if (back_buffer_)
         {
            back_buffer_->AddRef();
            const ULONG refs = back_buffer_->Release();
            if (refs > 1)
            {
               Log(reshade::log::level::warning, std::format("ResizeBuffers refused, the back buffer is still referenced ({} references)", refs - 1));
               return DXGI_ERROR_INVALID_CALL;
            }
         }
         DXGI_SWAP_CHAIN_DESC1 new_desc = desc_;
         new_desc.Width = width;
         new_desc.Height = height;
         new_desc.Format = format;
         if (buffer_count != 0)
            new_desc.BufferCount = buffer_count;
         new_desc.Flags = flags;
         ComPtr<ID3D11Texture2D> new_back_buffer;
         const HRESULT hr = CreateBackBuffer(new_desc, new_back_buffer);
         if (FAILED(hr))
            return hr;
         back_buffer_ = std::move(new_back_buffer);
         desc_ = new_desc;
         // The real swap chain follows on the next present
         return S_OK;
      }
      HRESULT STDMETHODCALLTYPE ResizeTarget(const DXGI_MODE_DESC* new_target_parameters) override { return S_OK; } // The window stays as the game made it
      HRESULT STDMETHODCALLTYPE GetContainingOutput(IDXGIOutput** output) override
      {
         if (!output)
            return E_POINTER;
         *output = nullptr;
         ComPtr<IDXGIDevice> dxgi_device;
         ComPtr<IDXGIAdapter> adapter;
         if (FAILED(device_.As(&dxgi_device)) || FAILED(dxgi_device->GetAdapter(&adapter)))
            return DXGI_ERROR_NOT_FOUND;
         const HMONITOR monitor = MonitorFromWindow(hwnd_, MONITOR_DEFAULTTONEAREST);
         ComPtr<IDXGIOutput> first_output;
         ComPtr<IDXGIOutput> current_output;
         for (UINT i = 0; SUCCEEDED(adapter->EnumOutputs(i, &current_output)); i++)
         {
            DXGI_OUTPUT_DESC output_desc = {};
            if (SUCCEEDED(current_output->GetDesc(&output_desc)) && output_desc.Monitor == monitor)
            {
               *output = current_output.Detach();
               return S_OK;
            }
            if (!first_output)
               first_output = current_output;
            current_output = nullptr;
         }
         if (!first_output)
            return DXGI_ERROR_NOT_FOUND;
         *output = first_output.Detach();
         return S_OK;
      }
      HRESULT STDMETHODCALLTYPE GetFrameStatistics(DXGI_FRAME_STATISTICS* stats) override
      {
         std::scoped_lock lock(mutex_);
         if (swapchain_12_)
            return swapchain_12_->GetFrameStatistics(stats);
         if (fallback_)
            return fallback_->GetFrameStatistics(stats);
         return DXGI_ERROR_FRAME_STATISTICS_DISJOINT;
      }
      HRESULT STDMETHODCALLTYPE GetLastPresentCount(UINT* last_present_count) override
      {
         if (!last_present_count)
            return E_POINTER;
         *last_present_count = present_count_;
         return S_OK;
      }

      // IDXGISwapChain1
      HRESULT STDMETHODCALLTYPE GetDesc1(DXGI_SWAP_CHAIN_DESC1* desc) override
      {
         if (!desc)
            return E_POINTER;
         std::scoped_lock lock(mutex_);
         *desc = desc_;
         return S_OK;
      }
      HRESULT STDMETHODCALLTYPE GetFullscreenDesc(DXGI_SWAP_CHAIN_FULLSCREEN_DESC* desc) override
      {
         if (!desc)
            return E_POINTER;
         std::scoped_lock lock(mutex_);
         *desc = fullscreen_desc_;
         desc->Windowed = TRUE;
         return S_OK;
      }
      HRESULT STDMETHODCALLTYPE GetHwnd(HWND* hwnd) override
      {
         if (!hwnd)
            return E_POINTER;
         *hwnd = hwnd_;
         return S_OK;
      }
      HRESULT STDMETHODCALLTYPE GetCoreWindow(REFIID riid, void** unknown) override
      {
         if (unknown)
            *unknown = nullptr;
         return DXGI_ERROR_INVALID_CALL;
      }
      HRESULT STDMETHODCALLTYPE Present1(UINT sync_interval, UINT flags, const DXGI_PRESENT_PARAMETERS* present_parameters) override { return PresentImpl(sync_interval, flags); }
      BOOL STDMETHODCALLTYPE IsTemporaryMonoSupported() override { return FALSE; }
      HRESULT STDMETHODCALLTYPE GetRestrictToOutput(IDXGIOutput** restrict_to_output) override
      {
         if (!restrict_to_output)
            return E_POINTER;
         *restrict_to_output = nullptr;
         return S_OK;
      }
      HRESULT STDMETHODCALLTYPE SetBackgroundColor(const DXGI_RGBA* color) override
      {
         if (!color)
            return E_POINTER;
         background_color_ = *color;
         return S_OK;
      }
      HRESULT STDMETHODCALLTYPE GetBackgroundColor(DXGI_RGBA* color) override
      {
         if (!color)
            return E_POINTER;
         *color = background_color_;
         return S_OK;
      }
      HRESULT STDMETHODCALLTYPE SetRotation(DXGI_MODE_ROTATION rotation) override { return rotation == DXGI_MODE_ROTATION_IDENTITY ? S_OK : DXGI_ERROR_INVALID_CALL; }
      HRESULT STDMETHODCALLTYPE GetRotation(DXGI_MODE_ROTATION* rotation) override
      {
         if (!rotation)
            return E_POINTER;
         *rotation = DXGI_MODE_ROTATION_IDENTITY;
         return S_OK;
      }

      // IDXGISwapChain2
      HRESULT STDMETHODCALLTYPE SetSourceSize(UINT width, UINT height) override
      {
         std::scoped_lock lock(mutex_);
         if (width == 0 || height == 0 || width > desc_.Width || height > desc_.Height)
            return DXGI_ERROR_INVALID_CALL;
         source_width_ = width;
         source_height_ = height;
         return S_OK;
      }
      HRESULT STDMETHODCALLTYPE GetSourceSize(UINT* width, UINT* height) override
      {
         if (!width || !height)
            return E_POINTER;
         std::scoped_lock lock(mutex_);
         *width = source_width_ ? source_width_ : desc_.Width;
         *height = source_height_ ? source_height_ : desc_.Height;
         return S_OK;
      }
      HRESULT STDMETHODCALLTYPE SetMaximumFrameLatency(UINT max_latency) override
      {
         if (max_latency == 0 || max_latency > 16)
            return DXGI_ERROR_INVALID_CALL;
         max_frame_latency_ = max_latency;
         return S_OK;
      }
      HRESULT STDMETHODCALLTYPE GetMaximumFrameLatency(UINT* max_latency) override
      {
         if (!max_latency)
            return E_POINTER;
         *max_latency = max_frame_latency_;
         return S_OK;
      }
      HANDLE STDMETHODCALLTYPE GetFrameLatencyWaitableObject() override
      {
         if (!latency_semaphore_)
            return nullptr;
         HANDLE duplicate = nullptr; // The caller closes it
         DuplicateHandle(GetCurrentProcess(), latency_semaphore_, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS);
         return duplicate;
      }
      HRESULT STDMETHODCALLTYPE SetMatrixTransform(const DXGI_MATRIX_3X2_F* matrix) override { return DXGI_ERROR_INVALID_CALL; } // Only for composition swap chains
      HRESULT STDMETHODCALLTYPE GetMatrixTransform(DXGI_MATRIX_3X2_F* matrix) override { return DXGI_ERROR_INVALID_CALL; }

      // IDXGISwapChain3
      UINT STDMETHODCALLTYPE GetCurrentBackBufferIndex() override { return 0; } // Always the same texture
      HRESULT STDMETHODCALLTYPE CheckColorSpaceSupport(DXGI_COLOR_SPACE_TYPE color_space, UINT* support) override
      {
         if (!support)
            return E_POINTER;
         const bool supported = color_space == DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709 || color_space == DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709 || color_space == DXGI_COLOR_SPACE_RGB_FULL_G2084_NONE_P2020;
         *support = supported ? DXGI_SWAP_CHAIN_COLOR_SPACE_SUPPORT_FLAG_PRESENT : 0;
         return S_OK;
      }
      HRESULT STDMETHODCALLTYPE SetColorSpace1(DXGI_COLOR_SPACE_TYPE color_space) override
      {
         UINT support = 0;
         CheckColorSpaceSupport(color_space, &support);
         if (!support)
            return E_INVALIDARG;
         std::scoped_lock lock(mutex_);
         color_space_ = color_space;
         color_space_set_ = true;
         return S_OK;
      }
      HRESULT STDMETHODCALLTYPE ResizeBuffers1(UINT buffer_count, UINT width, UINT height, DXGI_FORMAT format, UINT flags, const UINT* creation_node_mask, IUnknown* const* present_queue) override
      {
         return ResizeBuffers(buffer_count, width, height, format, flags);
      }

      // IDXGISwapChain4
      HRESULT STDMETHODCALLTYPE SetHDRMetaData(DXGI_HDR_METADATA_TYPE type, UINT size, void* metadata) override
      {
         std::scoped_lock lock(mutex_);
         hdr_metadata_type_ = type;
         hdr_metadata_.assign(static_cast<uint8_t*>(metadata), static_cast<uint8_t*>(metadata) + (metadata ? size : 0));
         hdr_metadata_dirty_ = true;
         return S_OK;
      }

   private:
      enum class Mode
      {
         Uninitialized,
         D3D12,
         Fallback,
      };

      ProxySwapChain() = default;
      ~ProxySwapChain()
      {
         ShutdownD3D12();
         fallback_ = nullptr;
         if (latency_semaphore_)
            CloseHandle(latency_semaphore_);
         if (registered_)
         {
            g_active_proxy = nullptr;
            Log(reshade::log::level::info, "Proxy swap chain released");
         }
      }

      HRESULT Init(IDXGIFactory2* factory, IUnknown* device, HWND hwnd, const DXGI_SWAP_CHAIN_DESC1& desc, const DXGI_SWAP_CHAIN_FULLSCREEN_DESC* fullscreen_desc)
      {
         factory_ = factory;
         game_device_ = device;
         hwnd_ = hwnd;
         // Work with the native device, not ReShade's proxy (so none of our resources go through add-on events)
         ComPtr<ID3D11Device> device_11;
         if (FAILED(device->QueryInterface(IID_PPV_ARGS(&device_11))))
            return E_NOINTERFACE;
         ComPtr<ID3D11Device> unwrapped;
         if (SUCCEEDED(device_11->QueryInterface(IID_UnwrappedObject, reinterpret_cast<void**>(unwrapped.GetAddressOf()))) && unwrapped)
            device_11 = unwrapped;
         device_ = device_11;
         device_->GetImmediateContext(&context_);

         desc_ = desc;
         if (desc_.Width == 0 || desc_.Height == 0)
         {
            RECT client = {};
            GetClientRect(hwnd_, &client);
            desc_.Width = desc_.Width ? desc_.Width : std::max<LONG>(client.right, 1);
            desc_.Height = desc_.Height ? desc_.Height : std::max<LONG>(client.bottom, 1);
         }
         if (fullscreen_desc)
            fullscreen_desc_ = *fullscreen_desc;
         fullscreen_desc_.Windowed = TRUE;
         if (desc_.SampleDesc.Count > 1 || desc_.Stereo)
            return DXGI_ERROR_UNSUPPORTED; // Not handled (left to the real DXGI)
         const HRESULT hr = CreateBackBuffer(desc_, back_buffer_);
         if (FAILED(hr))
            return hr;
         if (desc_.Flags & DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT)
            latency_semaphore_ = CreateSemaphoreW(nullptr, LONG(max_frame_latency_), 16, nullptr);
         return S_OK;
      }

      HRESULT CreateBackBuffer(const DXGI_SWAP_CHAIN_DESC1& desc, ComPtr<ID3D11Texture2D>& texture)
      {
         const DXGI_FORMAT format = ToBackBufferFormat(desc.Format);
         if (format == DXGI_FORMAT_UNKNOWN)
         {
            Log(reshade::log::level::warning, std::format("Unsupported back buffer format {}", int(desc.Format)));
            return DXGI_ERROR_UNSUPPORTED;
         }
         D3D11_TEXTURE2D_DESC texture_desc = {};
         texture_desc.Width = desc.Width;
         texture_desc.Height = desc.Height;
         texture_desc.MipLevels = 1;
         texture_desc.ArraySize = 1;
         texture_desc.Format = format;
         texture_desc.SampleDesc.Count = 1;
         texture_desc.Usage = D3D11_USAGE_DEFAULT;
         texture_desc.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;
         if (desc.BufferUsage & DXGI_USAGE_UNORDERED_ACCESS)
            texture_desc.BindFlags |= D3D11_BIND_UNORDERED_ACCESS;
         const HRESULT hr = device_->CreateTexture2D(&texture_desc, nullptr, &texture);
         if (FAILED(hr))
            Log(reshade::log::level::error, std::format("Failed to create the back buffer ({}x{} format {}), hr = {:#010x}", desc.Width, desc.Height, int(format), unsigned(hr)));
         return hr;
      }

      HRESULT PresentImpl(UINT sync_interval, UINT flags)
      {
         if (flags & DXGI_PRESENT_TEST)
            return S_OK;
         std::scoped_lock lock(mutex_);
         if (FAILED(device_->GetDeviceRemovedReason()))
            return DXGI_ERROR_DEVICE_REMOVED;
         sync_interval = std::min(sync_interval, 4u);

         if (mode_ == Mode::Uninitialized)
         {
            mode_ = InitD3D12() ? Mode::D3D12 : Mode::Fallback;
            if (mode_ == Mode::Fallback)
               ShutdownD3D12();
         }
         if (mode_ == Mode::D3D12 && !PresentD3D12(sync_interval))
         {
            Log(reshade::log::level::error, "Switching to the DX11 fallback swap chain");
            ShutdownD3D12();
            mode_ = Mode::Fallback;
         }
         if (mode_ == Mode::Fallback)
            PresentFallback(sync_interval);

         present_count_++;
         if (latency_semaphore_)
            ReleaseSemaphore(latency_semaphore_, 1, nullptr);
         return S_OK; // Never hand presentation errors to the game, it would likely crash on them
      }

      // --- DX12 path ---
      bool InitD3D12()
      {
         if (!D3D12Interop::Init(interop_, device_.Get()))
            return false;
         if (FAILED(interop_.device_12->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&idle_fence_))))
            return false;
         idle_event_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
         if (!idle_event_)
            return false;
         ComPtr<IDXGIFactory5> factory_5;
         BOOL allow_tearing = FALSE;
         if (SUCCEEDED(factory_.As(&factory_5)) && SUCCEEDED(factory_5->CheckFeatureSupport(DXGI_FEATURE_PRESENT_ALLOW_TEARING, &allow_tearing, sizeof(allow_tearing))))
            tearing_supported_ = allow_tearing != FALSE;
         D3D12_DESCRIPTOR_HEAP_DESC heap_desc = {};
         heap_desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
         heap_desc.NumDescriptors = dx12_back_buffer_count;
         if (FAILED(interop_.device_12->CreateDescriptorHeap(&heap_desc, IID_PPV_ARGS(&rtv_heap_))))
            return false;
         rtv_descriptor_size_ = interop_.device_12->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
         Log(reshade::log::level::info, std::format("DX12 presentation initialized (tearing {})", tearing_supported_));
         return true;
      }

      bool FlushQueue12()
      {
         if (!interop_.command_queue || !idle_fence_)
            return true;
         const UINT64 value = ++idle_fence_value_;
         if (FAILED(interop_.command_queue->Signal(idle_fence_.Get(), value)))
            return false;
         if (idle_fence_->GetCompletedValue() >= value)
            return true;
         if (FAILED(idle_fence_->SetEventOnCompletion(value, idle_event_)))
            return false;
         return WaitForSingleObject(idle_event_, 2000) == WAIT_OBJECT_0;
      }

      void ShutdownD3D12()
      {
         const bool idle = FlushQueue12() && D3D12Interop::WaitForIdle(interop_);
         if (!idle)
         {
            Log(reshade::log::level::error, "The DX12 queue isn't idle, leaking its resources");
            for (auto& back_buffer : back_buffers_12_)
               back_buffer.Detach();
            swapchain_12_.Detach();
            frame_.resource_11.Detach();
            frame_.resource_12.Detach();
            interop_.command_queue.Detach();
         }
         for (auto& back_buffer : back_buffers_12_)
            back_buffer = nullptr;
         swapchain_12_ = nullptr;
         rtv_heap_ = nullptr;
         frame_ = {};
         idle_fence_ = nullptr;
         if (idle_event_)
            CloseHandle(idle_event_);
         idle_event_ = nullptr;
         D3D12Interop::Deinit(interop_);
         width_12_ = height_12_ = 0;
         format_12_ = DXGI_FORMAT_UNKNOWN;
      }

      bool AcquireBackBuffers12()
      {
         for (UINT i = 0; i < dx12_back_buffer_count; i++)
         {
            if (FAILED(swapchain_12_->GetBuffer(i, IID_PPV_ARGS(&back_buffers_12_[i]))))
               return false;
            D3D12_CPU_DESCRIPTOR_HANDLE rtv = rtv_heap_->GetCPUDescriptorHandleForHeapStart();
            rtv.ptr += SIZE_T(i) * rtv_descriptor_size_;
            interop_.device_12->CreateRenderTargetView(back_buffers_12_[i].Get(), nullptr, rtv);
         }
         return true;
      }

      void ApplyColorSpace12()
      {
         const DXGI_COLOR_SPACE_TYPE color_space = color_space_set_ ? color_space_ : DefaultColorSpace(format_12_);
         if (color_space == applied_color_space_)
            return;
         UINT support = 0;
         if (SUCCEEDED(swapchain_12_->CheckColorSpaceSupport(color_space, &support)) && (support & DXGI_SWAP_CHAIN_COLOR_SPACE_SUPPORT_FLAG_PRESENT) && SUCCEEDED(swapchain_12_->SetColorSpace1(color_space)))
            Log(reshade::log::level::info, std::format("DX12 swap chain color space {}", int(color_space)));
         else
            Log(reshade::log::level::warning, std::format("Color space {} isn't supported for presentation", int(color_space)));
         applied_color_space_ = color_space;
      }

      bool UpdateSwapchain12(UINT width, UINT height, DXGI_FORMAT format)
      {
         if (swapchain_12_ && width == width_12_ && height == height_12_ && format == format_12_)
            return true;
         const UINT flags = tearing_supported_ ? DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING : 0;
         if (swapchain_12_)
         {
            if (!FlushQueue12())
               return false;
            for (auto& back_buffer : back_buffers_12_)
               back_buffer = nullptr;
            const HRESULT hr = swapchain_12_->ResizeBuffers(dx12_back_buffer_count, width, height, format, flags);
            if (FAILED(hr))
            {
               Log(reshade::log::level::error, std::format("Failed to resize the DX12 swap chain, hr = {:#010x}", unsigned(hr)));
               return false;
            }
         }
         else
         {
            DXGI_SWAP_CHAIN_DESC1 desc = {};
            desc.Width = width;
            desc.Height = height;
            desc.Format = format;
            desc.SampleDesc.Count = 1;
            desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
            desc.BufferCount = dx12_back_buffer_count;
            desc.Scaling = DXGI_SCALING_STRETCH;
            desc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
            desc.AlphaMode = DXGI_ALPHA_MODE_IGNORE;
            desc.Flags = flags;
            ComPtr<IDXGISwapChain1> swapchain_1;
            HRESULT hr = RealCreateSwapChainForHwnd(factory_.Get(), interop_.command_queue.Get(), hwnd_, &desc, &swapchain_1);
            if (SUCCEEDED(hr))
               hr = swapchain_1.As(&swapchain_12_);
            if (FAILED(hr))
            {
               Log(reshade::log::level::error, std::format("Failed to create the DX12 swap chain ({}x{} format {}), hr = {:#010x}", width, height, int(format), unsigned(hr)));
               swapchain_12_ = nullptr;
               return false;
            }
            factory_->MakeWindowAssociation(hwnd_, DXGI_MWA_NO_ALT_ENTER);
            Log(reshade::log::level::info, std::format("Created the DX12 swap chain on the game window ({}x{} format {})", width, height, int(format)));
         }
         width_12_ = width;
         height_12_ = height;
         format_12_ = format;
         applied_color_space_ = DXGI_COLOR_SPACE_RESERVED; // Re-apply
         hdr_metadata_dirty_ = true;
         return AcquireBackBuffers12();
      }

      bool PresentD3D12(UINT sync_interval)
      {
         if (!D3D12Interop::UpdateSharedTextureFrom(interop_, frame_, back_buffer_.Get(), false, false))
            return false;
         const DXGI_FORMAT format = ToPresentFormat(frame_.format);
         if (format == DXGI_FORMAT_UNKNOWN || !UpdateSwapchain12(frame_.width, frame_.height, format))
            return false;
         ApplyColorSpace12();
         if (hdr_metadata_dirty_)
         {
            hdr_metadata_dirty_ = false;
            ComPtr<IDXGISwapChain4> swapchain_4;
            if (SUCCEEDED(swapchain_12_.As(&swapchain_4)))
               swapchain_4->SetHDRMetaData(hdr_metadata_type_, UINT(hdr_metadata_.size()), hdr_metadata_.empty() ? nullptr : hdr_metadata_.data());
         }

         // DX11: back buffer -> shared texture
         context_->CopyResource(frame_.resource_11.Get(), back_buffer_.Get());

         // DX12: shared texture -> DX12 back buffer
         ID3D12GraphicsCommandList* command_list = D3D12Interop::BeginCommandList(interop_, context_.Get());
         if (!command_list)
            return false;
         const UINT back_buffer_index = swapchain_12_->GetCurrentBackBufferIndex();
         ID3D12Resource* const back_buffer_12 = back_buffers_12_[back_buffer_index].Get();
         const bool debug_split = g_settings.debug_split;
         D3D12_RESOURCE_BARRIER barriers[2] = {};
         barriers[0].Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
         barriers[0].Transition.pResource = frame_.resource_12.Get();
         barriers[0].Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
         barriers[0].Transition.StateBefore = D3D12_RESOURCE_STATE_COMMON; // Shared textures are in the common state between command lists
         barriers[0].Transition.StateAfter = D3D12_RESOURCE_STATE_COPY_SOURCE;
         barriers[1] = barriers[0];
         barriers[1].Transition.pResource = back_buffer_12;
         barriers[1].Transition.StateBefore = D3D12_RESOURCE_STATE_PRESENT;
         barriers[1].Transition.StateAfter = debug_split ? D3D12_RESOURCE_STATE_RENDER_TARGET : D3D12_RESOURCE_STATE_COPY_DEST;
         command_list->ResourceBarrier(2, barriers);
         if (debug_split)
         {
            D3D12_CPU_DESCRIPTOR_HANDLE rtv = rtv_heap_->GetCPUDescriptorHandleForHeapStart();
            rtv.ptr += SIZE_T(back_buffer_index) * rtv_descriptor_size_;
            const float magenta[4] = {1.f, 0.f, 1.f, 1.f};
            command_list->ClearRenderTargetView(rtv, magenta, 0, nullptr);
            D3D12_RESOURCE_BARRIER to_copy = barriers[1];
            to_copy.Transition.StateBefore = D3D12_RESOURCE_STATE_RENDER_TARGET;
            to_copy.Transition.StateAfter = D3D12_RESOURCE_STATE_COPY_DEST;
            command_list->ResourceBarrier(1, &to_copy);
            D3D12_TEXTURE_COPY_LOCATION dst = {back_buffer_12, D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX};
            D3D12_TEXTURE_COPY_LOCATION src = {frame_.resource_12.Get(), D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX};
            const D3D12_BOX left_half = {0, 0, 0, frame_.width / 2, frame_.height, 1};
            command_list->CopyTextureRegion(&dst, 0, 0, 0, &src, &left_half);
            barriers[1].Transition.StateAfter = D3D12_RESOURCE_STATE_COPY_DEST; // So the swap below goes back to present
         }
         else
         {
            command_list->CopyResource(back_buffer_12, frame_.resource_12.Get());
         }
         for (auto& barrier : barriers)
            std::swap(barrier.Transition.StateBefore, barrier.Transition.StateAfter);
         command_list->ResourceBarrier(2, barriers);
         if (!D3D12Interop::ExecuteCommandList(interop_, context_.Get()))
            return false;

         const UINT present_flags = (sync_interval == 0 && tearing_supported_) ? DXGI_PRESENT_ALLOW_TEARING : 0;
         const HRESULT hr = swapchain_12_->Present(sync_interval, present_flags);
         if (FAILED(hr))
         {
            Log(reshade::log::level::error, std::format("DX12 Present failed, hr = {:#010x}", unsigned(hr)));
            return false;
         }
         if (!first_frame_logged_)
         {
            first_frame_logged_ = true;
            Log(reshade::log::level::info, "First frame presented through DX12");
         }
         return true;
      }

      // --- DX11 fallback path ---
      void PresentFallback(UINT sync_interval)
      {
         D3D11_TEXTURE2D_DESC desc = {};
         back_buffer_->GetDesc(&desc);
         const DXGI_FORMAT format = ToPresentFormat(desc.Format);
         const UINT flags = fallback_tearing_ ? DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING : 0;
         if (!fallback_ && !fallback_failed_)
         {
            ComPtr<IDXGIFactory5> factory_5;
            BOOL allow_tearing = FALSE;
            if (SUCCEEDED(factory_.As(&factory_5)) && SUCCEEDED(factory_5->CheckFeatureSupport(DXGI_FEATURE_PRESENT_ALLOW_TEARING, &allow_tearing, sizeof(allow_tearing))))
               fallback_tearing_ = allow_tearing != FALSE;
            DXGI_SWAP_CHAIN_DESC1 swapchain_desc = {};
            swapchain_desc.Width = desc.Width;
            swapchain_desc.Height = desc.Height;
            swapchain_desc.Format = format;
            swapchain_desc.SampleDesc.Count = 1;
            swapchain_desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
            swapchain_desc.BufferCount = 2;
            swapchain_desc.Scaling = DXGI_SCALING_STRETCH;
            swapchain_desc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
            swapchain_desc.AlphaMode = DXGI_ALPHA_MODE_IGNORE;
            swapchain_desc.Flags = fallback_tearing_ ? DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING : 0;
            const HRESULT hr = RealCreateSwapChainForHwnd(factory_.Get(), device_.Get(), hwnd_, &swapchain_desc, &fallback_);
            if (FAILED(hr))
            {
               Log(reshade::log::level::error, std::format("The DX11 fallback swap chain failed too, hr = {:#010x}: nothing can be shown", unsigned(hr)));
               fallback_failed_ = true;
               return;
            }
            factory_->MakeWindowAssociation(hwnd_, DXGI_MWA_NO_ALT_ENTER);
            fallback_width_ = desc.Width;
            fallback_height_ = desc.Height;
            fallback_format_ = format;
            Log(reshade::log::level::info, std::format("Presenting through a DX11 fallback swap chain ({}x{} format {})", desc.Width, desc.Height, int(format)));
         }
         if (!fallback_)
            return;
         if (desc.Width != fallback_width_ || desc.Height != fallback_height_ || format != fallback_format_)
         {
            // Its buffers are never bound by anyone (we only copy into them), so no state needs clearing
            if (FAILED(fallback_->ResizeBuffers(2, desc.Width, desc.Height, format, flags)))
               return;
            fallback_width_ = desc.Width;
            fallback_height_ = desc.Height;
            fallback_format_ = format;
         }
         ComPtr<ID3D11Texture2D> target;
         if (FAILED(fallback_->GetBuffer(0, IID_PPV_ARGS(&target))))
            return;
         context_->CopyResource(target.Get(), back_buffer_.Get());
         target = nullptr;
         fallback_->Present(sync_interval, (sync_interval == 0 && fallback_tearing_) ? DXGI_PRESENT_ALLOW_TEARING : 0);
      }

      std::atomic<ULONG> refs_ = 1;
      std::recursive_mutex mutex_;
      bool registered_ = false;

      ComPtr<IDXGIFactory2> factory_;
      ComPtr<IUnknown> game_device_; // As passed by the game (possibly ReShade's proxy), returned by GetDevice
      ComPtr<ID3D11Device> device_; // Native
      ComPtr<ID3D11DeviceContext> context_;
      HWND hwnd_ = nullptr;
      DXGI_SWAP_CHAIN_DESC1 desc_ = {};
      DXGI_SWAP_CHAIN_FULLSCREEN_DESC fullscreen_desc_ = {};
      ComPtr<ID3D11Texture2D> back_buffer_;

      std::atomic<UINT> present_count_ = 0;
      DXGI_RGBA background_color_ = {};
      UINT source_width_ = 0;
      UINT source_height_ = 0;
      std::atomic<UINT> max_frame_latency_ = 3;
      HANDLE latency_semaphore_ = nullptr;
      DXGI_COLOR_SPACE_TYPE color_space_ = DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709;
      bool color_space_set_ = false;
      DXGI_HDR_METADATA_TYPE hdr_metadata_type_ = DXGI_HDR_METADATA_TYPE_NONE;
      std::vector<uint8_t> hdr_metadata_;
      bool hdr_metadata_dirty_ = false;
      std::map<GUID, std::vector<uint8_t>, GuidLess> private_data_;
      std::map<GUID, ComPtr<IUnknown>, GuidLess> private_interfaces_;

      Mode mode_ = Mode::Uninitialized;
      // DX12
      D3D12Interop::Context interop_;
      D3D12Interop::SharedTexture frame_;
      ComPtr<IDXGISwapChain3> swapchain_12_;
      ComPtr<ID3D12Resource> back_buffers_12_[dx12_back_buffer_count];
      ComPtr<ID3D12DescriptorHeap> rtv_heap_;
      UINT rtv_descriptor_size_ = 0;
      ComPtr<ID3D12Fence> idle_fence_; // Our own fence for full queue flushes (the interop fence is shared with DX11)
      UINT64 idle_fence_value_ = 0;
      HANDLE idle_event_ = nullptr;
      bool tearing_supported_ = false;
      UINT width_12_ = 0;
      UINT height_12_ = 0;
      DXGI_FORMAT format_12_ = DXGI_FORMAT_UNKNOWN;
      DXGI_COLOR_SPACE_TYPE applied_color_space_ = DXGI_COLOR_SPACE_RESERVED;
      bool first_frame_logged_ = false;
      // DX11 fallback
      ComPtr<IDXGISwapChain1> fallback_;
      bool fallback_failed_ = false;
      bool fallback_tearing_ = false;
      UINT fallback_width_ = 0;
      UINT fallback_height_ = 0;
      DXGI_FORMAT fallback_format_ = DXGI_FORMAT_UNKNOWN;
   };

   bool ShouldIntercept(IUnknown* device, HWND hwnd)
   {
      if (t_nested > 0 || !g_settings.enabled || g_active_proxy.load() != nullptr)
         return false;
      if (!device || !hwnd || !IsWindow(hwnd) || GetAncestor(hwnd, GA_ROOT) != hwnd)
         return false;
      ComPtr<ID3D11Device> device_11;
      return SUCCEEDED(device->QueryInterface(IID_PPV_ARGS(&device_11))); // DX11 only (not DX12 queues, ours included)
   }

   HRESULT STDMETHODCALLTYPE Hook_CreateSwapChain(IDXGIFactory* factory, IUnknown* device, DXGI_SWAP_CHAIN_DESC* desc, IDXGISwapChain** swapchain)
   {
      if (desc && swapchain && ShouldIntercept(device, desc->OutputWindow))
      {
         ComPtr<IDXGIFactory2> factory_2;
         if (SUCCEEDED(factory->QueryInterface(IID_PPV_ARGS(&factory_2))))
         {
            DXGI_SWAP_CHAIN_DESC1 desc_1 = {};
            desc_1.Width = desc->BufferDesc.Width;
            desc_1.Height = desc->BufferDesc.Height;
            desc_1.Format = desc->BufferDesc.Format;
            desc_1.SampleDesc = desc->SampleDesc;
            desc_1.BufferUsage = desc->BufferUsage;
            desc_1.BufferCount = desc->BufferCount;
            desc_1.Scaling = DXGI_SCALING_STRETCH;
            desc_1.SwapEffect = desc->SwapEffect;
            desc_1.AlphaMode = DXGI_ALPHA_MODE_UNSPECIFIED;
            desc_1.Flags = desc->Flags;
            DXGI_SWAP_CHAIN_FULLSCREEN_DESC fullscreen_desc = {};
            fullscreen_desc.RefreshRate = desc->BufferDesc.RefreshRate;
            fullscreen_desc.ScanlineOrdering = desc->BufferDesc.ScanlineOrdering;
            fullscreen_desc.Scaling = desc->BufferDesc.Scaling;
            fullscreen_desc.Windowed = TRUE;
            if (!desc->Windowed)
               Log(reshade::log::level::warning, "The game asked for exclusive fullscreen, staying windowed");
            IDXGISwapChain1* swapchain_1 = nullptr;
            if (SUCCEEDED(ProxySwapChain::Create(factory_2.Get(), device, desc->OutputWindow, desc_1, &fullscreen_desc, &swapchain_1)))
            {
               *swapchain = swapchain_1;
               return S_OK;
            }
            Log(reshade::log::level::warning, "Couldn't create the proxy swap chain, the game gets a real one");
         }
      }
      t_nested++;
      const HRESULT hr = g_real_CreateSwapChain(factory, device, desc, swapchain);
      t_nested--;
      return hr;
   }

   HRESULT STDMETHODCALLTYPE Hook_CreateSwapChainForHwnd(IDXGIFactory2* factory, IUnknown* device, HWND hwnd, const DXGI_SWAP_CHAIN_DESC1* desc, const DXGI_SWAP_CHAIN_FULLSCREEN_DESC* fullscreen_desc, IDXGIOutput* restrict_to_output, IDXGISwapChain1** swapchain)
   {
      if (desc && swapchain && ShouldIntercept(device, hwnd))
      {
         if (fullscreen_desc && !fullscreen_desc->Windowed)
            Log(reshade::log::level::warning, "The game asked for exclusive fullscreen, staying windowed");
         if (SUCCEEDED(ProxySwapChain::Create(factory, device, hwnd, *desc, fullscreen_desc, swapchain)))
            return S_OK;
         Log(reshade::log::level::warning, "Couldn't create the proxy swap chain, the game gets a real one");
      }
      t_nested++;
      const HRESULT hr = g_real_CreateSwapChainForHwnd(factory, device, hwnd, desc, fullscreen_desc, restrict_to_output, swapchain);
      t_nested--;
      return hr;
   }

   // ------------------------------------------------------------------------------------------------
   // ReShade events: install the hooks as soon as a DX11 device is about to be created (before any swap chain)
   // ------------------------------------------------------------------------------------------------
   bool OnCreateDevice(reshade::api::device_api api, uint32_t& api_version)
   {
      if (api == reshade::api::device_api::d3d11)
         InstallHooks();
      return false;
   }

   bool OnCreateSwapchain(reshade::api::device_api api, reshade::api::swapchain_desc& desc, void* hwnd)
   {
      if (api == reshade::api::device_api::d3d11)
         InstallHooks(); // Last chance, this is called right before the real creation
      return false;
   }

   // Called from the game's "OnInit()": the hooks go in right before the first DX11 device/swap chain is created
   void Register()
   {
      reshade::register_event<reshade::addon_event::create_device>(OnCreateDevice);
      reshade::register_event<reshade::addon_event::create_swapchain>(OnCreateSwapchain);
   }
}
