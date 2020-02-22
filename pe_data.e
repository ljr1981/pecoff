note
	description: "Data about any or all PE Image files."
	design: "[
		The specifications for the data respository used by Current is
		specified by the Generic Parameter 'G -> PE_DATA_SPECS' such that
		variants can be implemented even in a homogenous system.
		]"
	ca_ignoredby : "CA070"

class
	PE_DATA [G -> PE_DATA_SPECS create default_create end]

inherit
	ANY
		redefine
			default_create
		end

create
	default_create

feature {NONE} -- Initialization

	default_create
			--<Precursor>
			-- Create `database' (if needed)
		local
			l_query: SQLITE_QUERY_STATEMENT
		do
			Precursor
			create l_query.make (SQL_create_table.twin, db_spec.Database)
			l_query.ensure_connected
			across
				l_query.execute_new as ic_results
			loop
				do_nothing -- there will be no results that we care about
			end
			l_query.dispose
		end

feature -- Ops

	delete_all_from_images
			-- Delete all from images table in `database'.
		local
			l_query: SQLITE_QUERY_STATEMENT
		do
			create l_query.make (SQL_delete_all_images, db_spec.Database)
			l_query.ensure_connected
			across
				l_query.execute_new as ic_results
			loop
				do_nothing -- there will be no results that we care about
			end
			l_query.dispose
		end

	save_or_update_image (a_image: PE_IMAGE_FILE)
			-- Save (INSERT) or UPDATE `a_image'.
		local
			l_query: SQLITE_QUERY_STATEMENT
			l_stmt: STRING
			l_count: INTEGER
		do
			l_stmt := sql_select_count (a_image)
			create l_query.make (l_stmt, db_spec.Database)
			l_query.ensure_connected
			across
				l_query.execute_new as ic_results
			from
				l_count := 0
			loop
				l_count := ic_results.item.integer_value (1)
			end
			l_query.dispose

			if l_count = 0 then
				l_stmt := sql_insert_image (a_image)
			else
				l_stmt := sql_update_image (a_image)
			end

			create l_query.make (l_stmt, db_spec.Database)
			l_query.ensure_connected
			across
				l_query.execute_new as ic_results
			loop
				do_nothing -- there will be no results that we care about
			end
			l_query.dispose
		end

feature {NONE} -- Implementation: Access

	db_spec: G attribute create Result end
			-- Data repository specification.

feature {NONE} -- Implementation: Queries

	SQL_create_table: STRING_8
			-- Create the image table being careful to only create if it does not yet exist.
		do
			Result := "CREATE TABLE IF NOT EXISTS images (file_name TEXT PRIMARY KEY, directory TEXT NOT NULL, machine INTEGER NOT NULL, characteristics INTEGER NOT NULL, is_dll INTEGER NOT NULL, is_exe INTEGER NOT NULL, is_obj INTEGER NOT NULL, is_lib INTEGER NOT NULL, file_date INTEGER NOT NULL, file_size INTEGER NOT NULL, file_type INTEGER NOT NULL);"
		end

	SQL_select_distinct (a_image: PE_IMAGE_FILE): STRING
			-- Select distinct image file_name data based on file_name.
		do
			Result := "SELECT DISTINCT " + fld_name_csv_list (NUL_image) + " FROM images WHERE " + fld_file_name (a_image) + ";"
		end

	SQL_select_count (a_image: PE_IMAGE_FILE): STRING
		do
			Result := "SELECT count(*) FROM images WHERE file_name='<<" + a_image.file_name_attached + ">>';"
		end

	SQL_select_dlls: STRING do Result := SQL_select_distinct_all + "WHERE " + fld_is_dll (NUL_image) + " = 1;" end
	SQL_select_exes: STRING do Result := SQL_select_distinct_all + "WHERE " + fld_is_exe (NUL_image) + " = 1;" end
	SQL_select_libs: STRING do Result := SQL_select_distinct_all + "WHERE " + fld_is_lib (NUL_image) + " = 1;" end
	SQL_select_objs: STRING do Result := SQL_select_distinct_all + "WHERE " + fld_is_obj (NUL_image) + " = 1;" end
			-- SQL SELECT DISTINCT ... WHERE ...

	SQL_select_distinct_all: STRING
			-- SQL SELECT DISTINCT f,f,f,f, ... all
		do
			Result := "SELECT DISTINCT "
			Result.append_string_general (fld_name_csv_list (NUL_image))
			Result.append_string_general (" FROM images ")
		end

	SQL_insert_image (a_image: PE_IMAGE_FILE): STRING
			-- Insert new image data based on UID, where the uid is a primary key and will
			-- 	overwrite with new data?
		do
			Result := "INSERT INTO images ("
			Result.append_string_general (fld_name_csv_list (NUL_image))
			Result.append_string_general (") VALUES( '")
			Result.append_string_general (fld_name_csv_values_list (a_image))
			Result.append_string_general (");")
		end

	SQL_update_image (a_image: PE_IMAGE_FILE): STRING
			-- Update existing UID with new image item data.
		do
			Result := "UPDATE images SET "
			Result.append_string_general (fld_name_csv_list (a_image))
			Result.append_string_general (" WHERE ")
			Result.append_string_general (fld_file_name (a_image))
			Result.append_string_general ("';")
		end

	SQL_delete_all_images: STRING
			-- SQL DELETE ... FROM ...
		do
			Result := "DELETE FROM images;"
		end

feature {NONE} -- Implementation: Constants

	NUL_image: detachable PE_IMAGE_FILE do Result := Void end

	fld_file_name (a_image: detachable PE_IMAGE_FILE): STRING 		do Result := "file_name"; 		if attached a_image then Result.append_string_general (" = '" + a_image.file_name_attached + "'") end end
	fld_directory (a_image: detachable PE_IMAGE_FILE): STRING 		do Result := "directory"; 		if attached a_image then Result.append_string_general (" = '" + a_image.directory_attached.path.name.out + "'") end end
	fld_machine (a_image: detachable PE_IMAGE_FILE): STRING 		do Result := "machine"; 		if attached a_image then Result.append_string_general (" = " + a_image.machine.out + " ") end end
	fld_characteristics (a_image: detachable PE_IMAGE_FILE): STRING do Result := "characteristics"; if attached a_image then Result.append_string_general (" = " + a_image.characteristics.out + " ") end end
	fld_is_exe (a_image: detachable PE_IMAGE_FILE): STRING 			do Result := "is_exe"; 			if attached a_image then Result.append_string_general (" = " + a_image.is_exe.to_integer.out + " ") end end
	fld_is_dll (a_image: detachable PE_IMAGE_FILE): STRING 			do Result := "is_dll"; 			if attached a_image then Result.append_string_general (" = " + a_image.is_dll_image.to_integer.out + " ") end end
	fld_is_lib (a_image: detachable PE_IMAGE_FILE): STRING 			do Result := "is_lib"; 			if attached a_image then Result.append_string_general (" = " + a_image.is_lib_image.to_integer.out + " ") end end
	fld_is_obj (a_image: detachable PE_IMAGE_FILE): STRING 			do Result := "is_obj"; 			if attached a_image then Result.append_string_general (" = " + a_image.is_obj_image.to_integer.out + " ") end end
	fld_file_date (a_image: detachable PE_IMAGE_FILE): STRING 		do Result := "file_date"; 		if attached a_image then Result.append_string_general (" = " + a_image.file_date.out + " ") end end
	fld_file_size (a_image: detachable PE_IMAGE_FILE): STRING 		do Result := "file_size"; 		if attached a_image then Result.append_string_general (" = " + a_image.file_size.out + " ") end end
	fld_file_type (a_image: detachable PE_IMAGE_FILE): STRING 		do Result := "file_type"; 		if attached a_image then Result.append_string_general (" = " + a_image.file_type.out + " ") end end

	fld_name_csv_list (a_image: detachable PE_IMAGE_FILE): STRING
			-- CSV list of field names.
		do
			Result := fld_file_name (a_image)
			Result.append_string_general (", ")
			Result.append_string_general (fld_directory (a_image))
			Result.append_string_general (", ")
			Result.append_string_general (fld_machine (a_image))
			Result.append_string_general (", ")
			Result.append_string_general (fld_characteristics (a_image))
			Result.append_string_general (", ")
			Result.append_string_general (fld_is_exe (a_image))
			Result.append_string_general (", ")
			Result.append_string_general (fld_is_dll (a_image))
			Result.append_string_general (", ")
			Result.append_string_general (fld_is_lib (a_image))
			Result.append_string_general (", ")
			Result.append_string_general (fld_is_obj (a_image))
			Result.append_string_general (", ")
			Result.append_string_general (fld_file_date (a_image))
			Result.append_string_general (", ")
			Result.append_string_general (fld_file_size (a_image))
			Result.append_string_general (", ")
			Result.append_string_general (fld_file_type (a_image))
		end

	fld_name_csv_values_list (a_image: PE_IMAGE_FILE): STRING
			-- CSV values list of field names.
		do
			Result := a_image.file_name_attached
			Result.append_string_general ("', '")
			Result.append_string_general (a_image.directory_attached.path.name.out)
			Result.append_string_general ("', ")
			Result.append_string_general (a_image.machine.out)
			Result.append_string_general (", ")
			Result.append_string_general (a_image.characteristics.out)
			Result.append_string_general (", ")
			Result.append_string_general (a_image.is_exe.to_integer.out)
			Result.append_string_general (", ")
			Result.append_string_general (a_image.is_dll_image.to_integer.out)
			Result.append_string_general (", ")
			Result.append_string_general (a_image.is_lib_image.to_integer.out)
			Result.append_string_general (", ")
			Result.append_string_general (a_image.is_obj_image.to_integer.out)
			Result.append_string_general (", ")
			Result.append_string_general (a_image.file_date.out)
			Result.append_string_general (", ")
			Result.append_string_general (a_image.file_size.out)
			Result.append_string_general (", ")
			Result.append_string_general (a_image.file_type.out)
		end

end
