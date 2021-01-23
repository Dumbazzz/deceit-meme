#include <Windows.h>
#include <iostream>
#include <vector>

namespace memory_utils
{
	#ifdef _WIN64
		#define DWORD_OF_BITNESS DWORD64
		#define PTRMAXVAL ((PVOID)0x000F000000000000)
	#elif _WIN32
		#define DWORD_OF_BITNESS DWORD
		#define PTRMAXVAL ((PVOID)0xFFF00000)
	#endif

	bool is_valid_ptr(PVOID ptr)
	{
		return (ptr >= (PVOID)0x10000) && (ptr < PTRMAXVAL) && ptr != nullptr && !IsBadReadPtr(ptr, sizeof(ptr));
	}

	HMODULE base;

	HMODULE get_base()
	{
		if (!base)
			base = GetModuleHandle(0);
		return base;
	}

	DWORD_OF_BITNESS get_base_address()
	{
		return (DWORD_OF_BITNESS)get_base();
	}

	template<class T>
	void write(std::vector<DWORD_OF_BITNESS>address, T value)
	{
		size_t lengh_array = address.size() - 1;
		DWORD_OF_BITNESS relative_address;
		relative_address = address[0];
		for (int i = 1; i < lengh_array + 1; i++)
		{
			if (is_valid_ptr((LPVOID)relative_address) == false)
				return;

			if (i < lengh_array)
				relative_address = *(DWORD_OF_BITNESS*)(relative_address + address[i]);
			else
			{
				T* writable_address = (T*)(relative_address + address[lengh_array]);
				*writable_address = value;
			}
		}
	}

	template<class T>
	T read(std::vector<DWORD_OF_BITNESS>address)
	{
		size_t lengh_array = address.size() - 1;
		DWORD_OF_BITNESS relative_address;
		relative_address = address[0];
		for (int i = 1; i < lengh_array + 1; i++)
		{
			if (is_valid_ptr((LPVOID)relative_address) == false)
				return T();

			if (i < lengh_array)
				relative_address = *(DWORD_OF_BITNESS*)(relative_address + address[i]);
			else
			{
				T readable_address = *(T*)(relative_address + address[lengh_array]);
				return readable_address;
			}
		}
	}

	void write_string(std::vector<DWORD_OF_BITNESS>address, char* value)
	{
		size_t lengh_array = address.size() - 1;
		DWORD_OF_BITNESS relative_address;
		relative_address = address[0];
		for (int i = 1; i < lengh_array + 1; i++)
		{
			if (is_valid_ptr((LPVOID)relative_address) == false)
				return;

			if (i < lengh_array)
				relative_address = *(DWORD_OF_BITNESS*)(relative_address + address[i]);
			else
			{
				char* writable_address = (char*)(relative_address + address[lengh_array]);
				*writable_address = *value;
			}
		}
	}

	char* read_string(std::vector<DWORD_OF_BITNESS>address)
	{
		size_t lengh_array = address.size() - 1;
		DWORD_OF_BITNESS relative_address;
		relative_address = address[0];
		for (int i = 1; i < lengh_array + 1; i++)
		{
			if (is_valid_ptr((LPVOID)relative_address) == false)
				return NULL;

			if (i < lengh_array)
				relative_address = *(DWORD_OF_BITNESS*)(relative_address + address[i]);
			else
			{
				char* readable_address = (char*)(relative_address + address[lengh_array]);
				return readable_address;
			}
		}
	}

	DWORD_OF_BITNESS get_module_size(DWORD_OF_BITNESS address)
	{
		return PIMAGE_NT_HEADERS(address + (DWORD_OF_BITNESS)PIMAGE_DOS_HEADER(address)->e_lfanew)->OptionalHeader.SizeOfImage;
	}

	DWORD_OF_BITNESS find_pattern(HMODULE module, const char* pattern, const char* mask)
	{
		DWORD_OF_BITNESS base = (DWORD_OF_BITNESS)module;
		DWORD_OF_BITNESS size = get_module_size(base);

		DWORD_OF_BITNESS patternLength = (DWORD_OF_BITNESS)strlen(mask);

		for (DWORD_OF_BITNESS i = 0; i < size - patternLength; i++)
		{
			bool found = true;
			for (DWORD_OF_BITNESS j = 0; j < patternLength; j++)
			{
				found &= mask[j] == '?' || pattern[j] == *(char*)(base + i + j);
			}

			if (found)
			{
				return base + i;
			}
		}

		return NULL;
	}

	void patch_instruction(DWORD_OF_BITNESS instruction_address, const char* instruction_bytes, int sizeof_instruction_byte)
	{
		DWORD dwOldProtection;

		VirtualProtect((LPVOID)instruction_address, sizeof_instruction_byte, PAGE_EXECUTE_READWRITE, &dwOldProtection);

		memcpy((LPVOID)instruction_address, instruction_bytes, sizeof_instruction_byte);

		VirtualProtect((LPVOID)instruction_address, sizeof_instruction_byte, dwOldProtection, NULL);

		FlushInstructionCache(GetCurrentProcess(), (LPVOID)instruction_address, sizeof_instruction_byte);
	}
}

namespace console
{
    FILE* out;
    void attach(const char* title)
    {
        AllocConsole();
        freopen_s(&out, "conout$", "w", stdout);
        SetConsoleTitle(title);
    }
}

void entry_thread(HMODULE module)
{
    console::attach("alternative: deceit base");

    std::cout << __FUNCTION__ << " > attach success\n";

	HMODULE game_module = GetModuleHandle("Game.DLL");

	if (!game_module)
	{
		std::cout << __FUNCTION__ << " > game.dll not found\n";
		FreeLibraryAndExitThread(module, 1);
	}

	DWORD64 game_module_address = (DWORD64)game_module;

    while (true)
    {
        if (GetAsyncKeyState(VK_DELETE))
            break;

		DWORD64 entity_list = memory_utils::read<DWORD64>( { game_module_address, 0xC2D4B0, 0x80 } );

		if (entity_list == NULL)
		{
			Sleep(100);
			continue;
		}

		int max_players_on_map = memory_utils::read<int>( { game_module_address, 0xBBF534 } );

		for (int i = 1; i <= max_players_on_map; i++)
		{
			DWORD64 entity = memory_utils::read<DWORD64>( { entity_list, (DWORD64)(i * 0x8) } );

			if (entity == NULL)
				continue;

			char* name = memory_utils::read_string( { entity, 0x480, 0x0 } );

			if (name == NULL)
				continue;
			
			float health = memory_utils::read<float>( { entity, 0xEC } );

			DWORD64 player_entity = memory_utils::read<DWORD64>({ entity, 0x140 });
			
			if (player_entity == NULL)
				continue;

			DWORD64 player_entity_movement_controller = memory_utils::read<DWORD64>( { player_entity, 0x60 } );

			if (player_entity_movement_controller == NULL)
				continue;

			float coord_x = memory_utils::read<float>( { player_entity_movement_controller, 0x78, 0x1E8 } );
			float coord_y = memory_utils::read<float>( { player_entity_movement_controller, 0x78, 0x1EC } );
			float coord_z = memory_utils::read<float>( { player_entity_movement_controller, 0x78, 0x1F0 } );

			std::cout 
				<< "player id: " << i 
				<< " name: " << name 
				<< " health: " << health 
				<< " coord.x: " << coord_x << " coord.y: " << coord_y << " coord.z: " << coord_z << std::endl;
		}

		Sleep(100);
		std::system("cls");
    }

	std::cout << __FUNCTION__ << " > free library...\n";

    FreeLibraryAndExitThread(module, 0);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)entry_thread, hModule, 0, 0);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

