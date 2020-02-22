note
	description: "Specifications needed by {PE_DATA}"

class
	PE_DATA_SPECS

feature -- Access

	database_name: STRING do Result := "pecoff.sqlite3" end

	database: SQLITE_DATABASE once create Result.make_create_read_write (database_name) end

end
