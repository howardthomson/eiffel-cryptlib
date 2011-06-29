note

	description: "Eiffel cryptlib SSL communication session"

class ECRYPT_SSL_SESSION

inherit

	ECRYPT_SESSION

create

	make

feature

	make is
			-- See p120
		local
			c_ret: INTEGER
		do
			c_ret := c_create_session ($session_handle, CRYPT_UNUSED, CRYPT_SESSION_SSL)
			if crypt_no_error (c_ret) then
				c_set_attribute (session_handle, CRYPT_ATTRIBUTE_BUFFERSIZE, 65536)
			else
			--	...
			end
		end
end