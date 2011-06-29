note

	description: "Eiffel cryptlib 'envelope' for encryption/decryption and hashing"

	see_manual: "See 'Data Enveloping' page 50 of manual-332.pdf"

class ECRYPT_ENVELOPE

inherit

	ECRYPT_HANDLE

feature -- Creation

	make
		local
		do
			last_error := c_create_envelope ($handle, CRYPT_UNUSED, CRYPT_FORMAT_CRYPTLIB)
			if last_error /= Crypt_ok then

				-- What then ...
			end
		end

feature -- Data in/out

	push_data (a_data: ARRAY [ INTEGER_8 ])
		local
			l_returned_count: INTEGER
		do
			last_error := c_push_data (handle, a_data.to_external, a_data.count, $l_returned_count)
			-- ...
		end
end