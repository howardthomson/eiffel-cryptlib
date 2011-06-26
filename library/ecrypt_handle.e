indexing

	description: "Eiffel cryptlib handle deferred class"

deferred class ECRYPT_HANDLE

inherit

	ECRYPT_EXTERNALS
	ECRYPT_CONSTANTS

feature

	handle: INTEGER

	last_error: INTEGER
			-- Return code from last called cryptlib C routine
end