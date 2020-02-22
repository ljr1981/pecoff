note
	description: "Tests of {PECOFF}."
	testing: "type/manual"

class
	PECOFF_TEST_SET

inherit
	EQA_TEST_SET
		rename
			assert as assert_old
		end

	EQA_COMMONLY_USED_ASSERTIONS
		undefine
			default_create
		end

	TEST_SET_BRIDGE
		undefine
			default_create
		end

feature -- Test routines

	pecoff_data_tests
			--
		local
			l_data: PE_DATA [PE_DATA_SPECS]
			l_image: PE_IMAGE_FILE
		do
				-- Prepare
			create l_data
			l_data.delete_all_from_images

				-- Common image item saving (insert or update)
			create l_image.make (".\_sample_images\gameux.dll")
			l_data.save_or_update_image (l_image)
			create l_image.make (".\_sample_images\gamingtcui.dll")
			l_data.save_or_update_image (l_image)
		end

	PECOFF_tests
			-- `PECOFF_tests'
		local
			l_item: PE_IMAGE_FILE
		do
			create l_item.make (".\_sample_images\gameux.dll")
			assert_integers_equal ("Pe_magic_code", 23_117, l_item.Pe_magic_code)
			assert_integers_equal ("PE", 20_480 + 69, l_item.convert_pair ('E', 'P'))
			assert_integers_equal ("machine", 34_404, l_item.machine.as_integer_32) -- 64 86 (0x8664) or 34_404
			assert_integers_equal ("characteristics", 61_440, l_item.characteristics.as_integer_32) -- F0 00 00 00 (0xF00000) or 61_440
			assert_32 ("dll", l_item.is_image_dll_file)

			create l_item.make (".\_sample_images\gamingtcui.dll")
			assert_integers_equal ("machine_2", 34_404, l_item.machine.as_integer_32) -- 64 86 (0x8664) or 34_404
			assert_integers_equal ("characteristics_2", 61_440, l_item.characteristics.as_integer_32) -- F0 00 00 00 (0xF00000) or 61_440
			assert_32 ("dll_2", l_item.is_image_dll_file)

				-- c:\Windows\SysWOW64\console.dll
			create l_item.make (".\_sample_images\console.dll")
			assert_integers_equal ("machine_3", 332, l_item.machine.as_integer_32) -- 4C 01 (0x014C) or 332
			assert_integers_equal ("characteristics_3", 57_344, l_item.characteristics.as_integer_32) -- E0 00 (0xE000) or 57_344
			assert_32 ("not_sys_file", not l_item.is_image_system_file)
			assert_32 ("dll_3", l_item.is_image_dll_file)

				-- c:\apps\winbuilds\doc\gcc-4.8.3\COPYING.LIB
			create l_item.make (".\_sample_images\COPYING.LIB")
			assert_integers_equal ("machine_4", 0, l_item.machine.as_integer_32) -- 0
			assert_integers_equal ("characteristics_4", 0, l_item.characteristics.as_integer_32) -- 0
			assert_32 ("not_sys_file_4", not l_item.is_image_system_file)
			assert_32 ("not_dll_4", not l_item.is_image_dll_file)
		end

end
