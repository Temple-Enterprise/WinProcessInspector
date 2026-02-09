#pragma once

namespace WinProcessInspector {
namespace Core {

namespace Config {
	constexpr int WINDOW_WIDTH = 1000;
	constexpr int WINDOW_HEIGHT = 700;
	constexpr int WINDOW_POS_X = 100;
	constexpr int WINDOW_POS_Y = 100;
	
	constexpr float UI_FONT_SIZE = 18.0f;
	constexpr float UI_TITLE_FONT_SIZE = 18.0f;
	constexpr float UI_PANEL_SPLIT_RATIO = 0.35f;
	
	constexpr int PROCESS_ICON_SIZE = 16;
	constexpr int MAX_DLL_PATH_LENGTH = 512;
	constexpr int MAX_PROCESS_FILTER_LENGTH = 256;
	constexpr int MAX_MEMORY_ADDRESS_LENGTH = 64;
	constexpr int MAX_MEMORY_SIZE_LENGTH = 64;
	constexpr int MAX_SEARCH_STRING_LENGTH = 256;
	
	constexpr int TITLE_BAR_HEIGHT = 25;
	
	constexpr float UI_WINDOW_PADDING_X = 12.0f;
	constexpr float UI_WINDOW_PADDING_Y = 8.0f;
	constexpr float UI_FRAME_PADDING_X = 10.0f;
	constexpr float UI_FRAME_PADDING_Y = 6.0f;
	constexpr float UI_ITEM_SPACING_X = 8.0f;
	constexpr float UI_ITEM_SPACING_Y = 6.0f;
	
	constexpr float UI_BUTTON_WIDTH = 80.0f;
	constexpr float UI_BUTTON_WIDTH_SMALL = 30.0f;
	
	constexpr float UI_COLOR_TEXT_R = 0.95f;
	constexpr float UI_COLOR_TEXT_G = 0.95f;
	constexpr float UI_COLOR_TEXT_B = 0.95f;
	
	constexpr float UI_COLOR_WINDOW_BG_R = 0.10f;
	constexpr float UI_COLOR_WINDOW_BG_G = 0.10f;
	constexpr float UI_COLOR_WINDOW_BG_B = 0.12f;
	
	constexpr float UI_COLOR_ACCENT_R = 0.40f;
	constexpr float UI_COLOR_ACCENT_G = 0.70f;
	constexpr float UI_COLOR_ACCENT_B = 1.00f;
	
	constexpr float UI_COLOR_BUTTON_CLOSE_R = 0.6f;
	constexpr float UI_COLOR_BUTTON_CLOSE_G = 0.1f;
	constexpr float UI_COLOR_BUTTON_CLOSE_B = 0.1f;
}

}
}
