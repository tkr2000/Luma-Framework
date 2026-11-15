// Assassin's Creed Unity (AnvilNext 2.0, D3D11) Luma mod.
//
// Stage 1: analysis skeleton.
// The game has no temporal upscaler, so DLSS SR / DLSS-G / DLSS-NR all need the game's own inputs found first:
// the anti-aliasing / post process position (where SR will replace it), the camera constants (to add jitter),
// the velocity buffer (the game has per object motion blur) and the main depth.
// This build changes nothing in the game's rendering. In Development builds Luma's panel lists every draw/dispatch of a
// captured frame with its shader hashes and resources, and can dump the game's shaders, which is what the next stages
// are built from.

#define GAME_ASSASSINS_CREED_UNITY 1

#define GEOMETRY_SHADER_SUPPORT 0
#define DISABLE_AUTO_DEBUGGER 1

#include "..\..\Core\core.hpp"

#include <cstdio>
#include <psapi.h>

// Temporary load diagnostics: the addon fails to initialize in this game (ReShade reports error 1114) while the same
// core loads in other games, so each step of the attach writes a line next to the addon.
namespace ACUDiag
{
   static wchar_t log_path[MAX_PATH] = {};

   static void Init(HMODULE module)
   {
      if (GetModuleFileNameW(module, log_path, MAX_PATH) == 0)
         return;
      wchar_t* slash = wcsrchr(log_path, L'\\');
      if (slash) *(slash + 1) = L'\0';
      wcscat_s(log_path, L"Luma-ACU-LoadDiag.txt");
   }

   static void Log(const char* text)
   {
      if (log_path[0] == L'\0')
         return;
      FILE* file = nullptr;
      if (_wfopen_s(&file, log_path, L"a") == 0 && file)
      {
         SYSTEMTIME time;
         GetLocalTime(&time);
         fprintf(file, "%02u:%02u:%02u.%03u [tid %lu] %s\n", time.wHour, time.wMinute, time.wSecond, time.wMilliseconds, GetCurrentThreadId(), text);
         fclose(file);
      }
   }
}

struct ACUGameDeviceData final : public GameDeviceData
{
   uint32_t draws_this_frame = 0;
   uint32_t dispatches_this_frame = 0;
   uint32_t last_frame_draws = 0;
   uint32_t last_frame_dispatches = 0;
};

class AssassinsCreedUnity final : public Game
{
   static ACUGameDeviceData& GetGameDeviceData(DeviceData& device_data)
   {
      return *static_cast<ACUGameDeviceData*>(device_data.game);
   }

public:
   void OnLoad(std::filesystem::path& file_path, bool failed) override
   {
      char reshade_info[256];
      HMODULE reshade_module = nullptr;
      // Find the module that exports ReShade's addon registration, like "reshade::register_addon" does
      HMODULE modules[1024];
      DWORD needed = 0;
      if (EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed))
      {
         for (DWORD i = 0; i < needed / sizeof(HMODULE); i++)
         {
            if (GetProcAddress(modules[i], "ReShadeRegisterAddon"))
            {
               reshade_module = modules[i];
               break;
            }
         }
      }
      const bool has_imgui_table = reshade_module && GetProcAddress(reshade_module, "ReShadeGetImGuiFunctionTable");
      sprintf_s(reshade_info, "OnLoad: register_addon %s | ReShade module %p | ImGui table export %s", failed ? "FAILED" : "ok", (void*)reshade_module, has_imgui_table ? "yes" : "no");
      ACUDiag::Log(reshade_info);
   }

   void OnInit(bool async) override
   {
      ACUDiag::Log("OnInit");
      // Keep the vanilla SDR look: the game's output and color pipeline are left as they are.
      GetShaderDefineData(POST_PROCESS_SPACE_TYPE_HASH).SetDefaultValue('0');
      GetShaderDefineData(EARLY_DISPLAY_ENCODING_HASH).SetDefaultValue('0');
      GetShaderDefineData(VANILLA_ENCODING_TYPE_HASH).SetDefaultValue('0');
      GetShaderDefineData(GAMMA_CORRECTION_TYPE_HASH).SetDefaultValue('0');
      GetShaderDefineData(UI_DRAW_TYPE_HASH).SetDefaultValue('0');

      luma_settings_cbuffer_index = 13;
      luma_data_cbuffer_index = 12;
      luma_ui_cbuffer_index = -1;
   }

   void OnCreateDevice(ID3D11Device* native_device, DeviceData& device_data) override
   {
      device_data.game = new ACUGameDeviceData;
   }

   DrawOrDispatchOverrideType OnDrawOrDispatch(ID3D11Device* native_device, ID3D11DeviceContext* native_device_context, CommandListData& cmd_list_data, DeviceData& device_data, reshade::api::shader_stage stages, const ShaderHashesList<OneShaderPerPipeline>& original_shader_hashes, bool is_custom_pass, bool& updated_cbuffers, std::function<void()>* original_draw_dispatch_func) override
   {
      if (!is_custom_pass)
      {
         auto& game_device_data = GetGameDeviceData(device_data);
         if ((stages & reshade::api::shader_stage::compute) != 0)
            game_device_data.dispatches_this_frame++;
         else
            game_device_data.draws_this_frame++;
      }
      return DrawOrDispatchOverrideType::None;
   }

   void OnPresent(ID3D11Device* native_device, DeviceData& device_data) override
   {
      auto& game_device_data = GetGameDeviceData(device_data);
      game_device_data.last_frame_draws = game_device_data.draws_this_frame;
      game_device_data.last_frame_dispatches = game_device_data.dispatches_this_frame;
      game_device_data.draws_this_frame = 0;
      game_device_data.dispatches_this_frame = 0;
      // Nothing is replaced yet, so the final display composition stays off.
      device_data.has_drawn_main_post_processing = false;
   }

   void DrawImGuiSettings(DeviceData& device_data) override
   {
      auto& game_device_data = GetGameDeviceData(device_data);
      ImGui::TextUnformatted("Stage 1 (analysis): the game's rendering is not modified yet.");
      ImGui::Text("Last frame: %u draws, %u dispatches", game_device_data.last_frame_draws, game_device_data.last_frame_dispatches);
   }

   void PrintImGuiAbout() override
   {
      ImGui::Text("Assassin's Creed Unity Luma mod (work in progress)");
      ImGui::Text("Built on Luma Framework by Pumbo (Filoppi) and contributors.");
   }
};

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
   if (ul_reason_for_call == DLL_PROCESS_ATTACH)
   {
      ACUDiag::Init(hModule);
      ACUDiag::Log("DllMain: process attach (static init done)");

      const char* project_name = PROJECT_NAME;
      const char* cleared_project_name = (project_name[0] == '_') ? (project_name + 1) : project_name;

      uint32_t mod_version = 1;
      Globals::SetGlobals(cleared_project_name, "Assassin's Creed Unity Luma mod", "", mod_version);

      // Analysis stage: don't touch the swapchain or any texture formats.
      swapchain_format_upgrade_type = TextureFormatUpgradesType::None;
      swapchain_upgrade_type = SwapchainUpgradeType::None;
      texture_format_upgrades_type = TextureFormatUpgradesType::None;
      enable_samplers_upgrade = false;

      game = new AssassinsCreedUnity();
   }

   const BOOL core_result = CoreMain(hModule, ul_reason_for_call, lpReserved);

   if (ul_reason_for_call == DLL_PROCESS_ATTACH)
      ACUDiag::Log(core_result ? "DllMain: CoreMain returned TRUE" : "DllMain: CoreMain returned FALSE");

   return TRUE; // Same as the template (CoreMain's result isn't forwarded)
}
