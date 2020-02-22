note
	description: "Microsoft Windows-based Image File (exe, dll, lib, obj)"
	EIS: "name=microsoft_pecoff", "src=https://wiki.osdev.org/PE"
	todo: "Make Current createable from a SQLite3 entry"

class
	PE_IMAGE_FILE

create
	make

feature {NONE} -- Initialization

	make (a_file_name: STRING)
			-- Initialize Current with `a_dir_path' and `a_file_name' (full path needed)
		note
			design: "[
				We do not need to load the entire file into memory. We only need enough
				to get at the PE COFF header and consume the data contained in it.
				Therefore, there is a little extra computing-cost incurred to get the PE
				location, reset to the start position and read the stream up to and including
				the COFF-header in its totality (plus a little).
				]"
		local
			l_file: PLAIN_TEXT_FILE
			l_count: INTEGER
		do
			create directory.make_with_path (create {PATH}.make_from_string (a_file_name.substring (1, a_file_name.last_index_of ('\', a_file_name.count))))
			file_name := a_file_name
			if attached directory as al_dir and then al_dir.exists then
				check has_file_name: attached file_name as al_file_name then
					create l_file.make_open_read (al_file_name)
						-- See if we are a PE-file and locate the COFF-header.
					l_file.read_stream (E_lfanew + Four_bytes)
					if convert_byte_stream (l_file.last_string.substring (Byte_1, Byte_2)) = Pe_magic_code then
						l_count := pe_coff_header_location (l_file.last_string)
					else
						has_no_pe_magic_code := True
					end
					is_pe_magic_code_tested := True

						-- If we have PE, then `process_stream' including PE-COFF-header
					if has_pe_magic_code_simple then
						l_file.start
						l_file.read_stream (l_count + PE_header_size_in_bytes) -- COFF-header plus a little
						process_stream (l_file.last_string)
					end
					file_date := l_file.date
					file_size := l_file.count
					file_type := l_file.file_info.type
					l_file.close
				end
			end
		ensure
			stored: has_directory_and_file_name
		end

feature -- Access

	file_date: INTEGER

	file_size: INTEGER

	file_type: INTEGER

	directory: detachable DIRECTORY

	directory_attached: DIRECTORY do check attached directory as al_result then Result := al_result end end

	file_name: detachable STRING

	file_name_attached: STRING do check attached file_name as al_result then Result := al_result end end

	has_directory_and_file_name: BOOLEAN
			--
		do
			Result := attached directory and then
						attached file_name
		end

	has_no_pe_magic_code: BOOLEAN
			-- Does the file at `directory' and `file_name' have `Pe_magic_code'?

	is_pe_magic_code_tested: BOOLEAN
			-- Has the `Pe_magic_code' been tested for in the incoming stream?

	has_pe_magic_code_post_process: BOOLEAN
			-- Does the file at `directory' and `file_name' have `Pe_magic_code'?
			-- Take into account the `machine' and `characteristics' values, which
			--	will be present if the PE-COFF header has been processed.
		do
			Result := has_no_pe_magic_code implies is_pe_magic_code_tested and then (machine > 0 and characteristics > 0)
		end

	has_pe_magic_code_simple: BOOLEAN
			-- Simplistic detection of our `file_name' having `Pe_magic_code'.
			--	The assumption is that this has been tested for.
		do
			Result := is_pe_magic_code_tested and then not has_no_pe_magic_code
		end

	is_exe: BOOLEAN
			-- Is `file_name' in `directory' an EXE file?
		do
			Result := has_directory_and_file_name and then
						is_file_executable and then
						not is_dll_image
		end

	is_lib_image: BOOLEAN
		do
			Result := has_directory_and_file_name and then
						attached file_name as al_file_name and then
						al_file_name.has_substring (".lib") and then
						not is_exe and then
						not is_dll_image
		end

	is_obj_image: BOOLEAN
			-- Is `file_name' in `directory' an OBJ file?
		do
			Result := has_directory_and_file_name and then
						attached file_name as al_file_name and then
						al_file_name.has_substring (".obj") and then
						not is_exe and then
						not is_dll_image
		end

	is_dll_image: BOOLEAN
			-- Is `file_name' in `directory' an DLL file?
		do
			Result := has_directory_and_file_name and then
						is_image_dll_file and then
						not is_exe
		end

feature {TEST_SET_BRIDGE, PE_DATA} -- Implementation: Access

	machine: INTEGER_64
			-- See EIS note link and "machine types" table.
		note
			EIS: "src=https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image"
		attribute
			Result := 0
		end

	machine_type: TUPLE [code, description: STRING]
			-- Based on `machine' code.
		note
			EIS: "src=https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image"
		do
			inspect
				machine.to_character_32
			when '%/0x1d3/' then
				Result := ["IMAGE_FILE_MACHINE_AM33", "Matsushita AM33"]
			when '%/0x8664/' then
				Result := ["IMAGE_FILE_MACHINE_AMD64", "x64"]
			when '%/0x1c0/' then
				Result := ["IMAGE_FILE_MACHINE_ARM", "ARM little endian"]
			when '%/0xaa64/' then
				Result := ["IMAGE_FILE_MACHINE_ARM64", "ARM64 little endian"]
			when '%/0x1c4/' then
				Result := ["IMAGE_FILE_MACHINE_ARMNT", "ARM Thumb-2 little endian"]
			when '%/0xebc/' then
				Result := ["IMAGE_FILE_MACHINE_EBC", "EFI byte code"]
			when '%/0x14c/' then
				Result := ["IMAGE_FILE_MACHINE_I386", "Intel 386 or later processors and compatible processors"]
			when '%/0x200/' then
				Result := ["IMAGE_FILE_MACHINE_IA64", "Intel Itanium processor family"]
			when '%/0x9041/' then
				Result := ["IMAGE_FILE_MACHINE_M32R", "Mitsubishi M32R little endian"]
			when '%/0x266/' then
				Result := ["IMAGE_FILE_MACHINE_MIPS16", "MIPS16"]
			when '%/0x366/' then
				Result := ["IMAGE_FILE_MACHINE_MIPSFPU", "MIPS with FPU"]
			when '%/0x466/' then
				Result := ["IMAGE_FILE_MACHINE_MIPSFPU16", "MIPS16 with FPU"]
			when '%/0x1f0/' then
				Result := ["IMAGE_FILE_MACHINE_POWERPC", "Power PC little endian"]
			when '%/0x1f1/' then
				Result := ["IMAGE_FILE_MACHINE_POWERPCFP", "Power PC with floating point support"]
			when '%/0x166/' then
				Result := ["IMAGE_FILE_MACHINE_R4000", "MIPS little endian"]
			when '%/0x5032/' then
				Result := ["IMAGE_FILE_MACHINE_RISCV32", "RISC-V 32-bit address space"]
			when '%/0x5064/' then
				Result := ["IMAGE_FILE_MACHINE_RISCV64", "RISC-V 64-bit address space"]
			when '%/0x5128/' then
				Result := ["IMAGE_FILE_MACHINE_RISCV128", "RISC-V 128-bit address space"]
			when '%/0x1a2/' then
				Result := ["IMAGE_FILE_MACHINE_SH3", "Hitachi SH3"]
			when '%/0x1a3/' then
				Result := ["IMAGE_FILE_MACHINE_SH3DSP", "Hitachi SH3 DSP"]
			when '%/0x1a6/' then
				Result := ["IMAGE_FILE_MACHINE_SH4", "Hitachi SH4"]
			when '%/0x1a8/' then
				Result := ["IMAGE_FILE_MACHINE_SH5", "Hitachi SH5"]
			when '%/0x1c2/' then
				Result := ["IMAGE_FILE_MACHINE_THUMB", "Thumb"]
			when '%/0x169/' then
				Result := ["IMAGE_FILE_MACHINE_WCEMIPSV2", "MIPS little-endian WCE v2"]
			else
				Result := ["IMAGE_FILE_MACHINE_UNKNOWN", "The contents of this field are assumed to be applicable to any machine type"]
			end
		end

	sections,
	time_date,
	size,
	characteristics: INTEGER_64
			--Characteristics
			--This is a field of bit flags, that show some characteristics of the file.

			--Constant Name							Bit Position / Mask		Description

	is_relocation_info_stripped_from_file: BOOLEAN
			--IMAGE_FILE_RELOCS_STRIPPED			1 / 0x0001				Relocation information was stripped from file
		do
			Result := (characteristics & ('%/0b0000000000000001/').code) = 1
		end

	is_file_executable: BOOLEAN
			--IMAGE_FILE_EXECUTABLE_IMAGE			2 / 0x0002				The file is executable
		do
			Result := (characteristics & ('%/0b0000000000000010/').code) = 2
		end

	is_coff_line_numbers_stripped_from_file: BOOLEAN
			--IMAGE_FILE_LINE_NUMS_STRIPPED			3 / 0x0004				COFF line numbers were stripped from file
		do
			Result := (characteristics & ('%/0b0000000000000100/').code) = 4
		end

	is_coff_symbol_table_entires_stripped_from_file: BOOLEAN
			--IMAGE_FILE_LOCAL_SYMS_STRIPPED		4 / 0x0008				COFF symbol table entries were stripped from file
		do
			Result := (characteristics & ('%/0b0000000000001000/').code) = 8
		end

	is_aggressive_trim_working_set: BOOLEAN
			--IMAGE_FILE_AGGRESIVE_WS_TRIM			5 / 0x0010				Aggressively trim the working set(obsolete)
		obsolete
			"do_not_use [2020-2-22]"
		do
			Result := (characteristics & ('%/0b0000000000010000/').code) = 16
		end

	is_app_can_handle_addresses_gt_2_gb: BOOLEAN
			--IMAGE_FILE_LARGE_ADDRESS_AWARE		6 / 0x0020				The application can handle addresses greater than 2 GB
		do
			Result := (characteristics & ('%/0b0000000001000000/').code) = 64
		end

	is_bytes_of_word_are_reversed: BOOLEAN
			--IMAGE_FILE_BYTES_REVERSED_LO			8 / 0x0080				The bytes of the word are reversed(obsolete)
		obsolete
			"do_not_use [2020-2-22]"
		do
			Result := (characteristics & ('%/0b0000000010000000/').code) = 128
		end

	is_supports_32_bit_words: BOOLEAN
			--IMAGE_FILE_32BIT_MACHINE				9 / 0x0100				The computer supports 32-bit words
		do
			Result := (characteristics & ('%/0b0000000100000000/').code) = 256
		end

	is_debugging_info_removed_and_stored_separately: BOOLEAN
			--IMAGE_FILE_DEBUG_STRIPPED				10 / 0x0200				Debugging information was removed and stored separately in another file
		do
			Result := (characteristics & ('%/0b0000001000000000/').code) = 512
		end

	is_image_on_removable_media: BOOLEAN
			--IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP	11 / 0x0400				If the image is on removable media, copy it to and run it from the swap file
		do
			Result := (characteristics & ('%/0b0000010000000000/').code) = 1_024
		end

	is_image_on_network: BOOLEAN
			--IMAGE_FILE_NET_RUN_FROM_SWAP			12 / 0x0800				If the image is on the network, copy it to and run it from the swap file
		do
			Result := (characteristics & ('%/0b0000100000000000/').code) = 2_048
		end

	is_image_system_file: BOOLEAN
			--IMAGE_FILE_SYSTEM						13 / 0x1000				The image is a system file
		do
			Result := (characteristics & ('%/0b0001000000000000/').code) = 4_096
		end

	is_image_dll_file: BOOLEAN
			--IMAGE_FILE_DLL						14 / 0x2000				The image is a DLL file
			-- 1111 0000 0000 0000
		do
			Result := (characteristics & ('%/0b0010000000000000/').code) = 8_192
		end

	is_image_should_only_be_ran_on_single_processor: BOOLEAN
			--IMAGE_FILE_UP_SYSTEM_ONLY				15 / 0x4000				The image should only be ran on a single processor computer
		do
			Result := (characteristics & ('%/0b0100000000000000/').code) = 16_384
		end

	is_bytes_of_word_are_reversable: BOOLEAN
			--IMAGE_FILE_BYTES_REVERSED_HI			16 / 0x8000				The bytes of the word are reversed(obsolete)
		obsolete
			"do_not_use [2020-2-22]"
		do
			Result := (characteristics & ('%/0b1000000000000000/').code) = 32_768
		end

feature {NONE} -- Implementation

	process_stream (a_stream: STRING)
			-- `process_stream' in `a_stream' if first two bytes are `Pe_magic_code'.
		do
			if convert_byte_stream (a_stream.substring (1, 2)) = Pe_magic_code then
				process_coff (a_stream, pe_coff_header_location (a_stream))
			else
				has_no_pe_magic_code := True
			end
		end

	process_coff (a_stream: STRING; a_offset: INTEGER)
			-- We now have `a_stream' with an `a_offset' start to the COFF header.
			--	With this information, we can now parse out what we're after.
		do
			machine := convert_byte_stream (a_stream.substring (a_offset + 4, a_offset + 4 + 1))
			characteristics := convert_byte_stream_reversed (a_stream.substring (a_offset + 4 + 16, a_offset + 4 + 16 + 1))
		end

feature {TEST_SET_BRIDGE} -- Implementation

	pe_coff_header_location (a_stream: STRING): INTEGER
			-- The correct way [to locate the PE COFF header] is to read a formerly reserved 4-byte
			--	address inside the MS-DOS header located at 0x3C (field commonly known as e_lfanew)
			--	which contains the address at which PE file signature is found, and PE file header
			--	follows immediately.
		require
			has_dos_header: convert_byte_stream (a_stream.substring (1, 2)) = pe_magic_code
		do
			Result := convert_byte_stream (a_stream.substring (e_lfanew + 1, e_lfanew + 4))
		end

	e_lfanew: INTEGER
			-- The location of the offset to the COFF-header.
		once
			Result := convert_bytes_to_integer (<<'%/0x3C/'>>)
		ensure
			Result = coff_header_pointer_start_byte
		end

	pe_magic_code: INTEGER
			-- The MS-DOS header begins with the magic code 0x5A4D and is 64 bytes long.
		once
			Result := convert_pair ('%/0x4D/', '%/0x5A/')
		ensure
			Result = 23_117
		end

	convert_pair (a_lsb: CHARACTER; a_msb: detachable CHARACTER): INTEGER
			-- Convert a one or two-byte pair of characters to an INTEGER value.
		local
			i: INTEGER
		do
			Result := convert_bytes_to_integer (<<a_lsb, a_msb>>)
		end

	convert_byte_stream_reversed (a_stream: STRING): INTEGER
			-- Convert byte-stream in `a_stream' as MSB to LSB
			--	(presumes incoming `a_stream' is LSB->MSB order
			--	 and then reverses it)
		local
			l_stream: STRING
		do
			across
				a_stream.new_cursor.reversed as ic
			from
				create l_stream.make_empty
			loop
				l_stream.append_character (ic.item)
			end
			Result := convert_byte_stream (l_stream)
		end

	convert_byte_stream (a_stream: STRING): INTEGER
			-- Convert byte-stream in `a_stream' as LSB to MSB
			--	(presumes incoming `a_stream' is LSB->MSB order)
		local
			l_array: ARRAY [CHARACTER]
		do
			create l_array.make_filled (' ', 1, a_stream.count)
			across
				a_stream as ic
			loop
				l_array.put (ic.item, ic.cursor_index)
			end
			Result := convert_bytes_to_integer (l_array)
		end

	convert_bytes_to_integer (a_bytes: ARRAY [detachable CHARACTER]): INTEGER
			-- Convert `a_bytes' into an INTEGER value
			--	(presume a LSB->MSB order)
		require
			four_bytes_only: a_bytes.count <= 4
		local
			m: INTEGER
		do
			across
				a_bytes as ic
			from
				m := 0
				Result := 0
			loop
				if attached ic.item as al_item then
					if m = 0 then
						Result := al_item.code
					else
						Result := (al_item.code * m) + Result
					end
				end
				if m = 0 then
					m := 256
				else
					m := m * 256
				end
			end
		end

	PE_header_size_in_bytes: INTEGER = 24
	Four_bytes: INTEGER = 4
	Byte_1: INTEGER = 1
	Byte_2: INTEGER = 2
	coff_header_pointer_start_byte: INTEGER = 60

invariant
	no_magic: has_no_pe_magic_code implies not has_pe_magic_code_simple
	has_magic: not has_no_pe_magic_code implies has_pe_magic_code_post_process

note
	EIS: "name=pecoff_structure", "src=https://www.red-gate.com/simple-talk/wp-content/uploads/blogbits/simon.cooper/PE%%20Headers%%20annotated.png"
	EIS: "name=nachos_coff_header_desc", "src=http://www.cas.mcmaster.ca/~rzheng/course/Nachos_Tutorial/nachossu22.html#x39-5300110"
	EIS: "name=general_coff", "src=https://wiki.osdev.org/COFF"
	EIS: "name=microsoft_pecoff", "src=https://wiki.osdev.org/PE"
	coff_header: "[
		50 45 00 00 64 86 or P E 0 0 x64-bit (86 64 little endian or 64 86)
		
		The PE signature starts with the magic number ‘PE’ (0x50, 0x45, 0x00, 0x00), 
		identifying this file as a PE executable, followed by the PE file header (also known as 
		the COFF header). The relevant field in this header is in the last two bytes, and it specifies 
		whether the file is an executable or a dll; bit 0x2000 is set for a dll.
		]"
	header_specification: "[
		Machine 
		This field determines what machine the file was compiled for. A hex value of 0x14C (332 in 
		decimal) is the code for an Intel 80386.
		
		Here's a list of possible values it can have.

		Value	Description
		0x14c	Intel 386
		0x8664	x64
		0x162	MIPS R3000
		0x168	MIPS R10000
		0x169	MIPS little endian WCI v2
		0x183	old Alpha AXP
		0x184	Alpha AXP
		0x1a2	Hitachi SH3
		0x1a3	Hitachi SH3 DSP
		0x1a6	Hitachi SH4
		0x1a8	Hitachi SH5
		0x1c0	ARM little endian
		0x1c2	Thumb
		0x1c4	ARMv7
		0x1d3	Matsushita AM33
		0x1f0	PowerPC little endian
		0x1f1	PowerPC with floating point support
		0x200	Intel IA64
		0x266	MIPS16
		0x268	Motorola 68000 series
		0x284	Alpha AXP 64-bit
		0x366	MIPS with FPU
		0x466	MIPS16 with FPU
		0xebc	EFI Byte Code
		0x8664	AMD AMD64
		0x9041	Mitsubishi M32R little endian
		0xaa64	ARM64 little endian
		0xc0ee	clr pure MSIL

		NumberOfSections
		The number of sections that are described at the end of the PE headers.

		TimeDateStamp
		32 bit time at which this header was generated: is used in the process of "Binding", see below.

		SizeOfOptionalHeader
		this field shows how long the "PE Optional Header" is that follows the COFF header.

		Characteristics
		This is a field of bit flags, that show some characteristics of the file.

		Constant Name						Bit Position / Mask		Description
		IMAGE_FILE_RELOCS_STRIPPED			1 / 0x0001				Relocation information was stripped from file
		IMAGE_FILE_EXECUTABLE_IMAGE			2 / 0x0002				The file is executable
		IMAGE_FILE_LINE_NUMS_STRIPPED		3 / 0x0004				COFF line numbers were stripped from file
		IMAGE_FILE_LOCAL_SYMS_STRIPPED		4 / 0x0008				COFF symbol table entries were stripped from file
		IMAGE_FILE_AGGRESIVE_WS_TRIM		5 / 0x0010				Aggressively trim the working set(obsolete)
		IMAGE_FILE_LARGE_ADDRESS_AWARE		6 / 0x0020				The application can handle addresses greater than 2 GB
		IMAGE_FILE_BYTES_REVERSED_LO		8 / 0x0080				The bytes of the word are reversed(obsolete)
		IMAGE_FILE_32BIT_MACHINE			9 / 0x0100				The computer supports 32-bit words
		IMAGE_FILE_DEBUG_STRIPPED			10 / 0x0200				Debugging information was removed and stored separately in another file
		IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP	11 / 0x0400				If the image is on removable media, copy it to and run it from the swap file
		IMAGE_FILE_NET_RUN_FROM_SWAP		12 / 0x0800				If the image is on the network, copy it to and run it from the swap file
		IMAGE_FILE_SYSTEM					13 / 0x1000				The image is a system file
		IMAGE_FILE_DLL						14 / 0x2000				The image is a DLL file
		IMAGE_FILE_UP_SYSTEM_ONLY			15 / 0x4000				The image should only be ran on a single processor computer
		IMAGE_FILE_BYTES_REVERSED_HI		16 / 0x8000				The bytes of the word are reversed(obsolete)

		Offset	Size	Field					Description
		------	----	-----					----------------------------------------------------------------------------
		0		8		Name					An 8-byte, null-padded ASCII string. There is no terminating null if the
												string is exactly eight characters long. For longer names, this field contains
												a slash (/) followed by ASCII representation of a decimal number: this number
												is an offset into the string table. Executable images do not use a string
												table and do not support section names longer than eight characters. Long
												names in object files will be truncated if emitted to an executable file.

		8		4		VirtualSize				Total size of the section when loaded into memory. If this value is greater
												than Size of Raw Data, the section is zero-padded. This field is valid only
												for executable images and should be set to 0 for object files.

		12		4		VirtualAddress			For executable images this is the address of the first byte of the
												section, when loaded into memory, relative to the image base. For
												object files, this field is the address of the first byte before
												relocation is applied; for simplicity, compilers should set this
												to zero. Otherwise, it is an arbitrary value that is subtracted
												from offsets during relocation.

		16		4		SizeOfRawData			Size of the section (object file) or size of the initialized data on
												disk (image files). For executable image, this must be a multiple of
												FileAlignment from the optional header. If this is less than
												VirtualSize the remainder of the section is zero filled. Because
												this field is rounded while the VirtualSize field is not it is
												possible for this to be greater than VirtualSize as well. When a
												section contains only uninitialized data, this field should be 0.

		20		4		PointerToRawData		File pointer to section’s first page within the COFF file. For
												executable images, this must be a multiple of FileAlignment from
												the optional header. For object files, the value should be aligned
												on a four-byte boundary for best performance. When a section contains
												only uninitialized data, this field should be 0.

		24		4		PointerToRelocations	File pointer to beginning of relocation entries for the section.
												Set to 0 for executable images or if there are no relocations.

		28		4		PointerToLinenumbers	File pointer to beginning of line-number entries for the section.
												Set to 0 if there are no COFF line numbers.

		32		2		NumberOfRelocations		Number of relocation entries for the section. Set to 0 for executable
												images.

		34		2		NumberOfLinenumbers		Number of line-number entries for the section.

		36		4		Characteristics			Flags describing sections characteristics.
		]"
end
