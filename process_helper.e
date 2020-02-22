note
	description: "[
		Represenation of a {EG_PROCESS_HELPER}.
		]"
	purpose_and_design: "See end-of-class notes"

class
	PROCESS_HELPER

inherit
	ANY

feature -- Status Report

	has_file_in_path (a_name: STRING): BOOLEAN
			-- `has_file_in_path' as `a_name'?
		local
			l_result,
			l_msg: STRING
		do
			l_msg := dos_where_not_found_message.twin
			l_result := output_of_command ("where " + a_name, ".").to_string_8
			Result := not l_result.same_string (l_msg) xor {PLATFORM}.is_unix
		end

feature -- Basic Operations

	last_error: INTEGER
			-- Number of `last_error' detected.

--	progress_updater: detachable EG_PROGRESS_UPDATER
--			-- Entity responsible for updating progress (if any).

--	progress_updater_attached: attached like progress_updater
--			-- An attached version of `progress_updater'.
--		do
--			check attached progress_updater as al_item then
--				Result := al_item
--			end
--		end

--	set_progress_updater (a_updater: attached like progress_updater)
--			-- Set the `progress_updater' to `a_updater' reference.
--		do
--			progress_updater := a_updater
--		ensure
--			set: attached progress_updater as al_item and then al_item ~ a_updater
--		end

	output_of_command (a_command_line: READABLE_STRING_32; a_directory: detachable READABLE_STRING_32): STRING_32
                -- `output_of_command' `a_command_line' launched in `a_directory' (e.g. "." = Current directory).
		require
			cmd_not_empty: not a_command_line.is_empty
			dir_not_empty: attached a_directory as al_dir implies not al_dir.is_empty
		local
			l_process: BASE_PROCESS
			l_buffer: SPECIAL [NATURAL_8]
			l_result: STRING_32
			l_args: ARRAY [STRING_32]
			l_cmd: STRING_32
			l_list: LIST [READABLE_STRING_32]
			i: INTEGER
		do
			create Result.make_empty
			l_list := a_command_line.split (' ')
			l_cmd := l_list [1]
			if l_list.count >= 2 then
				create l_args.make_filled ({STRING_32} "", 1, l_list.count - 1)
				across
					2 |..| l_list.count as ic
				loop
					l_args.put (l_list [ic.item], ic.item - 1)
				end
			end
			l_process := (create {BASE_PROCESS_FACTORY}).process_launcher (l_cmd, l_args, a_directory)
			l_process.set_hidden (True)
			l_process.redirect_output_to_stream
			l_process.redirect_error_to_same_as_output
			l_process.launch
			if l_process.launched then
				from
					create l_buffer.make_filled (0, 512)
					i := 0
				until
					l_process.has_output_stream_closed or else l_process.has_output_stream_error
				loop
					l_buffer := l_buffer.aliased_resized_area_with_default (0, l_buffer.capacity)
					l_process.read_output_to_special (l_buffer)
					l_result := converter.console_encoding_to_utf32 (console_encoding, create {STRING_8}.make_from_c_substring ($l_buffer, 1, l_buffer.count))
					l_result.prune_all ({CHARACTER_32} '%R')
					Result.append (l_result)
					update_progress (i, Result)
					i := i + 1
				end
				l_process.wait_for_exit
			end
		end

	update_progress (a_counter: INTEGER; a_result: STRING_32)
			-- `update_progress' at `a_counter' with `a_result'.
			-- Sending updates through `progress_updater' (if any).
		note
			design: "[
				Our `progress_updater' tells us about a "progress-block"--that is--a block of
				percentage points (start-to-end) (i.e. 1-to-100 or 10-to-29 or whatever range).
				
				We also expect our incoming `a_result' string to contain 0-1-or-more "lines"
				as signified by a new-line character (i.e. %N).
				
				Our `progress_updater' also tells us an estimated-number-of-lines expected in
				the `a_result'.
				
				Therefore--our job here is to determine what percent of the block we've
				completed, add that to out starting percent, and then update the progress
				bar (defined by our `progress_updater') with the new percentage result.
				]"
		local
			l_percent: INTEGER
		do
--			application.Logger.write_information ("update_progress with counter: " + a_counter.out + " and result: " + a_result + "%N")
			if attached progress_updater as al_updater and then attached al_updater.on_output_agent as al_update_agent then
				al_update_agent.call (a_result)
--				application.Logger.write_information (a_result)
				if
					attached {INTEGER} a_result.occurrences ('%N') as al_line_count and then
					attached {INTEGER} (al_line_count / al_updater.estimated_item_count).truncated_to_integer as al_block_percent and then
					al_block_percent <= al_updater.end_percent
				then
					l_percent := al_updater.start_percent + al_block_percent
					al_updater.progress_bar.set_value (l_percent)
--					application.Logger.write_information (l_percent.out + "%%%N")
				end
			end
		end

	launch_fail_handler (a_result: STRING)
			-- `launch_fail_handler' at `a_result'
		do
			last_error_result := a_result
		end

	last_error_result: detachable STRING
			-- The `last_error_result' (if any).

feature -- Status Report: Wait for Exit

	is_not_wait_for_exit: BOOLEAN
			-- Flag for `is_not_wait_for_exit'.

	is_wait_for_exit: BOOLEAN
			-- Computed flag for `is_wait_for_exit'.
		do
			Result := not is_not_wait_for_exit
		end

	set_do_not_wait_for_exit
		do
			is_not_wait_for_exit := True
		end

	set_wait_for_exit
		do
			is_not_wait_for_exit := False
		end

feature {NONE} -- Code page conversion

	converter: LOCALIZED_PRINTER
			-- Converter of the input data into Unicode.
		once
			create Result
		end

	console_encoding: ENCODING
			-- Current console encoding.
		once
			Result := (create {SYSTEM_ENCODINGS}).console_encoding
		end

feature {TEST_SET_BRIDGE} -- Implementation: Constants

	DOS_where_not_found_message: STRING = "INFO: Could not find files for the given pattern(s).%N"

;note
	design: "[
		These "helper" features are designed to assist with
		use of the {PROCESS_IMP} and {PROCESS_FACTORY}.
		]"

end
