note
	description: "Tests of {PECOFF}."
	testing: "type/manual"
	EIS: "name=readme", "src=README.md", "protocol=text"

class
	PECOFF_TEST_SET

inherit
	TEST_SET_SUPPORT

	TEST_SET_BRIDGE
		undefine
			default_create
		end

feature -- Test routines

	pecoff_data_tests
			-- Loading a local test pecoff.sqlite3 file with some test data.
		local
			l_data: PE_DATA [PE_DATA_SPECS]
			l_image: PE_IMAGE_FILE
		do
				-- Prepare
			create l_data
			l_data.delete_all_from_images

				-- Common image item saving (insert or update)
			create l_image.make (".\_sample_images\gameux.dll"); l_data.save_or_update_image (l_image)
			create l_image.make (".\_sample_images\gamingtcui.dll"); l_data.save_or_update_image (l_image)
			create l_image.make (".\_sample_images\console.dll"); l_data.save_or_update_image (l_image)
			create l_image.make (".\_sample_images\COPYING.LIB"); l_data.save_or_update_image (l_image)
			create l_image.make (".\_sample_images\d3dcompiler_47.dll"); l_data.save_or_update_image (l_image)
			create l_image.make (".\_sample_images\DEMImporter.dll"); l_data.save_or_update_image (l_image)
			create l_image.make (".\_sample_images\Microsoft.AspNetCore.Server.Kestrel.Transport.Libuv.dll"); l_data.save_or_update_image (l_image)
			create l_image.make (".\_sample_images\Microsoft.Extensions.ObjectPool.dll"); l_data.save_or_update_image (l_image)
			create l_image.make (".\_sample_images\Microsoft.VisualStudio.TestPlatform.ObjectModel.resources.dll"); l_data.save_or_update_image (l_image)
			create l_image.make (".\_sample_images\msdia140.dll"); l_data.save_or_update_image (l_image)
			create l_image.make (".\_sample_images\sni.dll"); l_data.save_or_update_image (l_image)
			create l_image.make (".\_sample_images\vidpcore.dll"); l_data.save_or_update_image (l_image)
			create l_image.make (".\_sample_images\xinput1_3.dll"); l_data.save_or_update_image (l_image)
		end

	PECOFF_tests
			-- `PECOFF_tests'
		local
			l_item: PE_IMAGE_FILE
		do
			create l_item.make (".\_sample_images\gameux.dll")
			assert_integers_equal ("Pe_magic_code", 23_117, l_item.Pe_magic_code)
			assert_integers_equal ("PE", 20_480 + 69, l_item.convert_pair ('E', 'P'))
			assert_integers_equal ("machine", 34_404, l_item.machine.as_integer_32)
			assert_strings_equal ("machine_name", "IMAGE_FILE_MACHINE_AMD64", l_item.machine_type.code)
			assert_integers_equal ("characteristics", 61_440, l_item.characteristics.as_integer_32)
			assert_32 ("dll", l_item.is_image_dll_file)

			create l_item.make (".\_sample_images\gamingtcui.dll")
			assert_integers_equal ("machine_2", 34_404, l_item.machine.as_integer_32)
			assert_strings_equal ("machine_2_name", "IMAGE_FILE_MACHINE_AMD64", l_item.machine_type.code)
			assert_integers_equal ("characteristics_2", 61_440, l_item.characteristics.as_integer_32)
			assert_32 ("dll_2", l_item.is_image_dll_file)

				-- c:\Windows\SysWOW64\console.dll
			create l_item.make (".\_sample_images\console.dll")
			assert_integers_equal ("machine_3", 332, l_item.machine.as_integer_32)
			assert_strings_equal ("machine_3_name", "IMAGE_FILE_MACHINE_I386", l_item.machine_type.code)
			assert_integers_equal ("characteristics_3", 57_344, l_item.characteristics.as_integer_32)
			assert_32 ("not_sys_file", not l_item.is_image_system_file)
			assert_32 ("dll_3", l_item.is_image_dll_file)

				-- c:\apps\winbuilds\doc\gcc-4.8.3\COPYING.LIB
			create l_item.make (".\_sample_images\COPYING.LIB")
			assert_integers_equal ("machine_4", 0, l_item.machine.as_integer_32)
			assert_strings_equal ("machine_4_name", "IMAGE_FILE_MACHINE_UNKNOWN", l_item.machine_type.code)
			assert_integers_equal ("characteristics_4", 0, l_item.characteristics.as_integer_32)
			assert_32 ("not_sys_file_4", not l_item.is_image_system_file)
			assert_32 ("not_dll_4", not l_item.is_image_dll_file)

				-- .\_sample_images\d3dcompiler_47.dll
			create l_item.make (".\_sample_images\d3dcompiler_47.dll")
			assert_integers_equal ("machine_5", 34_404, l_item.machine.as_integer_32)
			assert_strings_equal ("machine_5_name", "IMAGE_FILE_MACHINE_AMD64", l_item.machine_type.code)
			assert_integers_equal ("characteristics_5", 61_440, l_item.characteristics.as_integer_32)
			assert_32 ("sys_file_5", l_item.is_image_system_file)
			assert_32 ("dll_5", l_item.is_image_dll_file)

				-- .\_sample_images\DEMImporter.dll
			create l_item.make (".\_sample_images\DEMImporter.dll")
			assert_integers_equal ("machine-6", 2_950, l_item.machine.as_integer_32)
			assert_strings_equal ("machine_name-6", "IMAGE_FILE_MACHINE_UNKNOWN", l_item.machine_type.code)
			assert_integers_equal ("characteristics-6", 34, l_item.characteristics.as_integer_32)

			assert_32 ("is_app_can_handle_addresses_gt_2_gb-6", not l_item.is_app_can_handle_addresses_gt_2_gb)
			assert_32 ("is_coff_line_numbers_stripped_from_file-6", not l_item.is_coff_line_numbers_stripped_from_file)
			assert_32 ("is_coff_symbol_table_entires_stripped_from_file-6", not l_item.is_coff_symbol_table_entires_stripped_from_file)
			assert_32 ("is_debugging_info_removed_and_stored_separately-6", not l_item.is_debugging_info_removed_and_stored_separately)
			assert_32 ("is_dll_image-6", not l_item.is_dll_image)
			assert_32 ("is_exe-6", l_item.is_exe)
			assert_32 ("is_file_executable-6", l_item.is_file_executable)
			assert_32 ("is_image_dll_file-6", not l_item.is_image_dll_file)
			assert_32 ("is_image_on_network-6", not l_item.is_image_on_network)
			assert_32 ("is_image_on_removable_media-6", not l_item.is_image_on_removable_media)
			assert_32 ("is_image_should_only_be_ran_on_single_processor-6", not l_item.is_image_should_only_be_ran_on_single_processor)
			assert_32 ("is_image_system_file-6", not l_item.is_image_system_file)
			assert_32 ("is_lib_image-6", not l_item.is_lib_image)
			assert_32 ("is_obj_image-6", not l_item.is_obj_image)
			assert_32 ("is_pe_magic_code_tested-6", l_item.is_pe_magic_code_tested)
			assert_32 ("is_relocation_info_stripped_from_file-6", not l_item.is_relocation_info_stripped_from_file)
			assert_32 ("is_supports_32_bit_words-6", not l_item.is_supports_32_bit_words)

				-- .\_sample_images\Microsoft.AspNetCore.Server.Kestrel.Transport.Libuv.dll
			create l_item.make (".\_sample_images\Microsoft.AspNetCore.Server.Kestrel.Transport.Libuv.dll")
			assert_integers_equal ("machine-7", 25_600, l_item.machine.as_integer_32)
			assert_strings_equal ("machine_name-7", "IMAGE_FILE_MACHINE_UNKNOWN", l_item.machine_type.code)
			assert_integers_equal ("characteristics-7", 240, l_item.characteristics.as_integer_32)

			assert_32 ("is_app_can_handle_addresses_gt_2_gb-7", l_item.is_app_can_handle_addresses_gt_2_gb)
			assert_32 ("is_coff_line_numbers_stripped_from_file-7", not l_item.is_coff_line_numbers_stripped_from_file)
			assert_32 ("is_coff_symbol_table_entires_stripped_from_file-7", not l_item.is_coff_symbol_table_entires_stripped_from_file)
			assert_32 ("is_debugging_info_removed_and_stored_separately-7", not l_item.is_debugging_info_removed_and_stored_separately)
			assert_32 ("is_dll_image-7", not l_item.is_dll_image)
			assert_32 ("is_exe-7", not l_item.is_exe)
			assert_32 ("is_file_executable-7", not l_item.is_file_executable)
			assert_32 ("is_image_dll_file-7", not l_item.is_image_dll_file)
			assert_32 ("is_image_on_network-7", not l_item.is_image_on_network)
			assert_32 ("is_image_on_removable_media-7", not l_item.is_image_on_removable_media)
			assert_32 ("is_image_should_only_be_ran_on_single_processor-7", not l_item.is_image_should_only_be_ran_on_single_processor)
			assert_32 ("is_image_system_file-7", not l_item.is_image_system_file)
			assert_32 ("is_lib_image-7", not l_item.is_lib_image)
			assert_32 ("is_obj_image-7", not l_item.is_obj_image)
			assert_32 ("is_pe_magic_code_tested-7", l_item.is_pe_magic_code_tested)
			assert_32 ("is_relocation_info_stripped_from_file-7", not l_item.is_relocation_info_stripped_from_file)
			assert_32 ("is_supports_32_bit_words-7", not l_item.is_supports_32_bit_words)

		end

end
