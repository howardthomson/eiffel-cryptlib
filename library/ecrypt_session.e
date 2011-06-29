note

	description: "Eiffel cryptlib communication session"

	descendants: "[
		Common ancestor to:
			ECRYPT_CMP_SESSION
			ECRYPT_OCSP_SESSION
			ECRYPT_RTCS_SESSION
			ECRYPT_SCEP_SESSION
			ECRYPT_SSH_SESSION
			ECRYPT_SSL_SESSION
			ECRYPT_TSP_SESSION
	]"

deferred class ECRYPT_SESSION

inherit

	ECRYPT_HANDLE

feature

	session_handle: INTEGER

	close is
			-- Terminate session
		do
			c_destroy_session (session_handle)
		end
end