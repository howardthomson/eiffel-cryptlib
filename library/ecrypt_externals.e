indexing

	description: "External routines for Eiffel cryptlib"

	TODO: "[
		Add externals for socket/stream I/O interception
	]"

class ECRYPT_EXTERNALS

inherit

	ECRYPT_CONSTANTS

feature -- General Functions

	-- Initialise and shut down cryptlib

	c_init: INTEGER is external "C" alias "cryptInit" end
	c_end : INTEGER is external "C" alias "cryptEnd"  end

	-- Query cryptlibs capabilities

	c_query_capability (
			a_type: INTEGER;		-- CRYPT_ALGO_TYPE cryptAlgo,
			an_info: POINTER		-- CRYPT_QUERY_INFO *cryptQueryInfo
			): INTEGER is
		require
		--	valid_type: valid_algorithm_type(a_type)
			valid_ptr: an_info /= default_pointer
		external "C"
		alias "cryptQueryCapability"
		end							

	-- Create and destroy an encryption context

	c_create_context (
			a_context	: POINTER;		--	CRYPT_CONTEXT C_PTR cryptContext,
			a_user:		: INTEGER;		--	CRYPT_USER cryptUser,
			an_algorithm: INTEGER		--	CRYPT_ALGO_TYPE cryptAlgo
			): INTEGER is
		require
			valid_context: a_context /= default_pointer
		--	valid_user: valid_user(a_user)
		--	valid_algorithm: valid_algorithm(an_algorithm)
		external "C"
		alias "cryptCreateContext"
		end
							  
	c_destroy_context (
			a_context	: INTEGER		-- C_IN CRYPT_CONTEXT cryptContext
			): INTEGER is
		external "C"
		alias "cryptDestroyContext"
		end

	-- Generic "destroy an object" function

	c_destroy_object (
			an_object	: INTEGER		-- C_IN CRYPT_HANDLE cryptObject
			): INTEGER is
		external "C"
		alias "cryptDestroyObject"
		end

	-- Generate a key into a context

	c_generate_key (
			a_context	: INTEGER		-- C_IN CRYPT_CONTEXT cryptContext
			): INTEGER is
		external "C"
		alias "cryptGenerateKey"
		end
	
	c_generate_key_async (
			a_context	: INTEGER		-- C_IN CRYPT_CONTEXT cryptContext
			): INTEGER is
		external "C"
		alias "cryptGenerateKeyAsync"
		end
	
	c_async_query (
			an_object	: INTEGER		-- C_IN CRYPT_HANDLE cryptObject
			): INTEGER is
		external "C"
		alias "cryptAsyncQuery"
		end
	
	c_async_cancel (
			an_object	: INTEGER		-- C_IN CRYPT_HANDLE cryptObject
			): INTEGER is
		external "C"
		alias "cryptAsyncCancel"
		end

	-- Encrypt/decrypt/hash a block of memory

	c_encrypt (
			a_context	: INTEGER;		-- C_IN CRYPT_CONTEXT cryptContext
			a_buffer	: POINTER;		-- C_INOUT void C_PTR buffer
			a_length	: INTEGER		-- C_IN int length
			): INTEGER is
		external "C"
		alias "cryptEncrypt"
		end
						
	c_decrypt (
			a_context	: INTEGER;		--	C_IN CRYPT_CONTEXT cryptContext
			a_buffer	: POINTER;		--	C_INOUT void C_PTR buffer
			a_length	: INTEGER		--	C_IN int length
			): INTEGER is
		external "C"
		alias "cryptDecrypt"
		end

	-- Get/set/delete attribute functions

	c_set_attribute (
			a_handle	: INTEGER;		--	C_IN CRYPT_HANDLE cryptHandle
			a_type		: INTEGER;		--	C_IN CRYPT_ATTRIBUTE_TYPE attributeType
			a_value		: INTEGER		--	C_IN int value
			): INTEGER is
		external "C"
		alias "cryptSetAttribute"
		end
							 
	c_set_attribute_string (
			a_handle	: INTEGER;		--	C_IN CRYPT_HANDLE cryptHandle
			a_type		: INTEGER;		--	C_IN CRYPT_ATTRIBUTE_TYPE attributeType
			a_value		: POINTER;		--	C_IN void C_PTR value
			a_length	: INTEGER		--	C_IN int valueLength
			): INTEGER is
		external "C"
		alias "cryptSetAttributeString"
		end
								   
	c_get_attribute (
			a_handle	: INTEGER;		--	C_IN CRYPT_HANDLE cryptHandle
			a_type		: INTEGER;		--	C_IN CRYPT_ATTRIBUTE_TYPE attributeType
			a_value		: INTEGER		--	C_OUT int C_PTR value
			): INTEGER is
		external "C"
		alias "cryptGetAttribute"
		end
							 
	c_get_attribute_string (
			a_handle	: INTEGER;		--	C_IN CRYPT_HANDLE cryptHandle
			a_type		: INTEGER;		--	C_IN CRYPT_ATTRIBUTE_TYPE attributeType
			a_value		: POINTER;		--	C_OUT void C_PTR value
			a_length	: INTEGER		--	C_OUT int C_PTR valueLength
			): INTEGER is
		external "C"
		alias "cryptGetAttributeString"
		end
								   
	c_delete_attribute (
			a_handle	: INTEGER;		--	C_IN CRYPT_HANDLE cryptHandle
			a_type		: INTEGER		--	C_IN CRYPT_ATTRIBUTE_TYPE attributeType
			): INTEGER is
		external "C"
		alias "cryptDeleteAttribute"
		end

	--	Oddball functions: Add random data to the pool, query an encoded signature
	--	or key data.  These are due to be replaced once a suitable alternative can
	--	be found

	c_add_random (
			a_data		: POINTER;		--	C_IN void C_PTR randomData,
			a_length	: INTEGER		--	C_IN int randomDataLength );
			): INTEGER is
		external "C"
		alias "cryptAddRandom"
		end
	
	c_query_object (
			a_data		: POINTER;		--	C_IN void C_PTR objectData,
			a_length	: INTEGER;		--	C_IN int objectDataLength,
			an_info		: POINTER		--	C_OUT CRYPT_OBJECT_INFO C_PTR cryptObjectInfo );
			): INTEGER is
		external "C"
		alias "cryptQueryObject"
		end

feature -- Mid-level Encryption Functions

	-- Export and import an encrypted session key

	c_export_key (
			an_encrypted_key	: POINTER;	--	C_OUT void C_PTR encryptedKey,
			a_max_length		: INTEGER;	--	C_IN int encryptedKeyMaxLength,
			a_length			: POINTER;	--	C_OUT int C_PTR encryptedKeyLength,
			a_export_key		: INTEGER;	--	C_IN CRYPT_HANDLE exportKey,
			a_context			: INTEGER	--	C_IN CRYPT_CONTEXT sessionKeyContext );
			): INTEGER is
		external "C"
		alias "cryptExportKey"
		end
						  
	 c_export_key_ex (
			an_encrypted_key	 : POINTER;	--	C_OUT void C_PTR encryptedKey
			a_max_length		 : INTEGER;	--	C_IN int encryptedKeyMaxLength
			a_length_ptr		 : POINTER;	--	C_OUT int C_PTR encryptedKeyLength
			a_format_type		 : INTEGER;	--	C_IN CRYPT_FORMAT_TYPE formatType
			an_export_key		 : INTEGER;	--	C_IN CRYPT_HANDLE exportKey
			a_session_key_context: INTEGER	--	C_IN CRYPT_CONTEXT sessionKeyContext
			): INTEGER is
		external "C"
		alias "cryptExportKeyEx"
		end
							
	c_import_key (
			an_encrypted_key	: POINTER;	--	C_IN void C_PTR encryptedKey
			a_key_length		: INTEGER;	--	C_IN int encryptedKeyLength
			a_key				: INTEGER;	--	C_IN CRYPT_CONTEXT importKey
			a_context			: INTEGER	--	C_IN CRYPT_CONTEXT sessionKeyContext
			): INTEGER is
		external "C"
		alias "cryptImportKey"
		end
						  
	c_import_key_ex (
			an_encrypted_key	: POINTER;	--	C_IN void C_PTR encryptedKey
			a_key_length		: INTEGER;	--	C_IN int encryptedKeyLength
			an_import_key		: INTEGER;	--	C_IN CRYPT_CONTEXT importKey
			a_context			: INTEGER;	--	C_IN CRYPT_CONTEXT sessionKeyContext
			a_returned_context	: POINTER	--	C_OUT CRYPT_CONTEXT C_PTR returnedContext
			): INTEGER is
		external "C"
		alias "cryptImportKeyEx"
		end

	-- Create and check a digital signature

	c_create_signature (
			a_returned_signature: POINTER;	--	C_OUT void C_PTR signature
			a_mex_length		: INTEGER;	--	C_IN int signatureMaxLength
			a_length			: POINTER;	--	C_OUT int C_PTR signatureLength
			a_signature_context	: INTEGER;	--	C_IN CRYPT_CONTEXT signContext
			a_hash_context		: INTEGER	--	C_IN CRYPT_CONTEXT hashContext
			): INTEGER is
		external "C"
		alias "cryptCreateSignature"
		end
								
	 c_create_signature_ex (
			a_signature_ptr		: POINTER;	--	C_OUT void C_PTR signature
			a_max_length		: INTEGER;	--	C_IN int signatureMaxLength
			a_length_ptr		: POINTER;	--	C_OUT int C_PTR signatureLength
			a_format_type		: INTEGER;	--	C_IN CRYPT_FORMAT_TYPE formatType
			a_signature_context	: INTEGER;	--	C_IN CRYPT_CONTEXT signContext
			a_hash_context		: INTEGER;	--	C_IN CRYPT_CONTEXT hashContext
			a_data				: INTEGER	--	C_IN CRYPT_CERTIFICATE extraData
			): INTEGER is
		external "C"
		alias "cryptCreateSignatureEx"
		end
								  
	c_check_signature (
			a_signature			: POINTER;	--	C_IN void C_PTR signature
			a_length			: INTEGER;	--	C_IN int signatureLength
			a_sig_key			: INTEGER;	--	C_IN CRYPT_HANDLE sigCheckKey
			a_hash_context		: INTEGER	--	C_IN CRYPT_CONTEXT hashContext
			): INTEGER is
		external "C"
		alias "cryptCheckSignature"
		end
							   
	c_check_signature_ex (
			a_signature			: POINTER;	--	C_IN void C_PTR signature
			a_length			: INTEGER;	--	C_IN int signatureLength
			a_sig_key			: INTEGER;	--	C_IN CRYPT_HANDLE sigCheckKey
			a_hash_context		: INTEGER;	--	C_IN CRYPT_CONTEXT hashContext
			a_data				: POINTER	--	C_OUT CRYPT_HANDLE C_PTR extraData
			): INTEGER is
		external "C"
		alias "cryptCheckSignatureEx"
		end

feature -- Keyset Functions

	-- Open and close a keyset

	c_keyset_open (
			a_keyset	: POINTER;		--	C_OUT CRYPT_KEYSET C_PTR keyset
			a_user		: INTEGER;		--	C_IN CRYPT_USER cryptUser
			a_type		: INTEGER;		--	C_IN CRYPT_KEYSET_TYPE keysetType
			a_name		: POINTER;		--	C_IN C_STR name,
			a_options	: INTEGER		--	C_IN CRYPT_KEYOPT_TYPE options
			): INTEGER is
		external "C"
		alias "cryptKeysetOpen"
		end
						   
	c_keyset_close (
			a_keyset	: INTEGER		--	C_IN CRYPT_KEYSET keyset
			): INTEGER is
		external "C"
		alias "cryptKeysetClose"
		end

	-- Get a key from a keyset

	c_get_public_key (
			a_keyset		: INTEGER;	--	C_IN CRYPT_KEYSET keyset
			a_context		: POINTER;	--	C_OUT CRYPT_CONTEXT C_PTR cryptContext
			a_key_id_type	: INTEGER;	--	C_IN CRYPT_KEYID_TYPE keyIDtype
			a_key_id		: POINTER	--	C_IN C_STR keyID
			): INTEGER is
		external "C"
		alias "cryptGetPublicKey"
		end
							 
	c_get_private_key (
			a_keyset		: INTEGER;	--	C_IN CRYPT_KEYSET keyset
			a_context		: POINTER;	--	C_OUT CRYPT_CONTEXT C_PTR cryptContext
			a_key_type		: INTEGER;	--	C_IN CRYPT_KEYID_TYPE keyIDtype
			a_key_id		: POINTER;	--	C_IN C_STR keyID
			a_password		: POINTER	--	C_IN C_STR password
			): INTEGER is
		external "C"
		alias "cryptGetPrivateKey"
		end

	-- Add/delete a key to/from a keyset

	 c_add_public_key (
			a_keyset		: INTEGER;	--	C_IN CRYPT_KEYSET keyset
			a_certificate	: INTEGER	--	C_IN CRYPT_CERTIFICATE certificate
			): INTEGER is
		external "C"
		alias "cryptAddPublicKey"
		end

	 c_add_private_key (
			a_keyset		: INTEGER;	--	C_IN CRYPT_KEYSET keyset
			a_key			: INTEGER;	--	C_IN CRYPT_HANDLE cryptKey
			a_password		: POINTER	--	C_IN C_STR password
			): INTEGER is
		external "C"
		alias "cryptAddPrivateKey"
		end
							  
	c_delete_key (
			a_keyset		: INTEGER;	--	C_IN CRYPT_KEYSET keyset
			a_key_id_type	: INTEGER;	--	C_IN CRYPT_KEYID_TYPE keyIDtype
			a_key_id		: POINTER	--	C_IN C_STR keyID
			): INTEGER is
		external "C"
		alias "cryptDeleteKey"
		end

feature -- Certificate Functions

	-- Create/destroy a certificate

	c_create_certificate (
			a_certificate	: POINTER;	--	C_OUT CRYPT_CERTIFICATE C_PTR certificate
			a_user			: INTEGER;	--	C_IN CRYPT_USER cryptUser
			a_type			: INTEGER	--	C_IN CRYPT_CERTTYPE_TYPE certType
			): INTEGER is
		external "C"
		alias "cryptCreateCert"
		end
						   
	 c_destroy_certificate (
			a_certificate	: INTEGER	--	C_IN CRYPT_CERTIFICATE certificate
			): INTEGER is
		external "C"
		alias "cryptDestroyCert"
		end

	--	Get/add/delete certificate extensions.  These are direct data insertion
	--	functions whose use is discouraged, so they fix the string at char *
	--	rather than C_STR

	c_get_cert_extension (
			a_certificate	: INTEGER;	--	C_IN CRYPT_CERTIFICATE certificate
			an_oid			: POINTER;	--	C_IN char C_PTR oid
			a_critical_flag	: POINTER;	--	C_OUT int C_PTR criticalFlag
			an_externsion	: POINTER;	--	C_OUT void C_PTR extension
			a_max_length	: INTEGER;	--	C_IN int extensionMaxLength
			a_extension_length: POINTER	--	C_OUT int C_PTR extensionLength
			): INTEGER is
		external "C"
		alias "cryptGetCertExtension"
		end
								 
	c_add_cert_extension (
			a_certificate	: INTEGER;	--	C_IN CRYPT_CERTIFICATE certificate
			an_oid			: POINTER;	--	C_IN char C_PTR oid
			a_critical_flag	: INTEGER;	--	C_IN int criticalFlag
			an_extension	: POINTER;	--	C_IN void C_PTR extension
			a_length		: INTEGER	--	C_IN int extensionLength
			): INTEGER is
		external "C"
		alias "cryptAddCertExtension"
		end
								 
	c_delete_cert_extension (
			a_certificate	: INTEGER;	--	C_IN CRYPT_CERTIFICATE certificate
			an_oid			: POINTER	--	C_IN char C_PTR oid
			): INTEGER is
		external "C"
		alias "cryptDeleteCertExtension"
		end

	-- Sign/sig.check a certificate/certification request

	c_sign_certificate (
			a_certificate	: INTEGER;	--	C_IN CRYPT_CERTIFICATE certificate
			a_context		: INTEGER	--	C_IN CRYPT_CONTEXT signContext
			): INTEGER is
		external "C"
		alias "cryptSignCert"
		end

	c_check_certificate (
			a_certificate	: INTEGER;	--	C_IN CRYPT_CERTIFICATE certificate
			a_key			: INTEGER	--	C_IN CRYPT_HANDLE sigCheckKey
			): INTEGER is
		external "C"
		alias "cryptCheckCert"
		end

	-- Import/export a certificate/certification request

	c_import_certificate (
			an_object		: POINTER;	--	C_IN void C_PTR certObject
			a_length		: INTEGER;	--	C_IN int certObjectLength
			a_user			: INTEGER;	--	C_IN CRYPT_USER cryptUser
			a_certificate	: POINTER	--	C_OUT CRYPT_CERTIFICATE C_PTR certificate
			): INTEGER is
		external "C"
		alias "cryptImportCert"
		end
						   
	c_export_certificate (
			an_object		: POINTER;	--	C_OUT void C_PTR certObject
			a_max_length	: INTEGER;	--	C_IN int certObjectMaxLength
			an_object_length: POINTER;	--	C_OUT int C_PTR certObjectLength
			a_type			: INTEGER;	--	C_IN CRYPT_CERTFORMAT_TYPE certFormatType
			a_certificate	: INTEGER	--	C_IN CRYPT_CERTIFICATE certificate
			): INTEGER is
		external "C"
		alias "cryptExportCert"
		end

	-- CA management functions

	c_ca_add_item (
			a_keyset		: INTEGER;	--	C_IN CRYPT_KEYSET keyset
			a_certificate	: INTEGER	--	C_IN CRYPT_CERTIFICATE certificate
			): INTEGER is
		external "C"
		alias "cryptCAAddItem"
		end
						  
	c_ca_get_item (
			a_keyset			: INTEGER;	--	C_IN CRYPT_KEYSET keyset
			a_certificate		: POINTER;	--	C_OUT CRYPT_CERTIFICATE C_PTR certificate
			a_certificate_type	: INTEGER;	--	C_IN CRYPT_CERTTYPE_TYPE certType
			a_key_id_type		: INTEGER;	--	C_IN CRYPT_KEYID_TYPE keyIDtype
			a_key_id			: POINTER	--	C_IN C_STR keyID
			): INTEGER is
		external "C"
		alias "cryptCAGetItem"
		end
						  
	c_ca_delete_item (
			a_keyset			: INTEGER;	--	C_IN CRYPT_KEYSET keyset
			a_certificate_type	: INTEGER;	--	C_IN CRYPT_CERTTYPE_TYPE certType
			a_key_id_type		: INTEGER;	--	C_IN CRYPT_KEYID_TYPE keyIDtype
			a_key_id			: POINTER	--	C_IN C_STR keyID
			): INTEGER is
		external "C"
		alias "cryptCADeleteItem"
		end
							 
	c_ca_certificate_management (
			a_certificate		: INTEGER;	--	C_OUT CRYPT_CERTIFICATE C_PTR certificate
			an_action			: INTEGER;	--	C_IN CRYPT_CERTACTION_TYPE action
			a_keyset			: INTEGER;	--	C_IN CRYPT_KEYSET keyset
			a_ca_key			: INTEGER;	--	C_IN CRYPT_CONTEXT caKey
			a_request			: INTEGER	--	C_IN CRYPT_CERTIFICATE certRequest
			): INTEGER is
		external "C"
		alias "cryptCACertManagement"
		end

feature -- Envelope and Session Functions

	-- Create/destroy an envelope

	c_create_envelope (
			an_envelope		: POINTER;	--	C_OUT CRYPT_ENVELOPE C_PTR envelope
			a_user			: INTEGER;	--	C_IN CRYPT_USER cryptUser
			a_type			: INTEGER	--	C_IN CRYPT_FORMAT_TYPE formatType
			): INTEGER is
		external "C"
		alias "cryptCreateEnvelope"
		end
							   
	c_destroy_envelope (
			an_envelope		: INTEGER	--	C_IN CRYPT_ENVELOPE envelope
			): INTEGER is
		external "C"
		alias "cryptDestroyEnvelope"
		end

	-- Create/destroy a session

	c_create_session (
			a_session		: POINTER;	--	C_OUT CRYPT_SESSION C_PTR session
			a_user			: INTEGER;	--	C_IN CRYPT_USER cryptUser
			a_type			: INTEGER	--	C_IN CRYPT_SESSION_TYPE formatType
			): INTEGER is
		external "C"
		alias "cryptCreateSession"
		end

	c_destroy_session (
			a_session		: INTEGER	--	C_IN CRYPT_SESSION session
			): INTEGER is
		external "C"
		alias "cryptDestroySession"
		end

	-- Add/remove data to/from and envelope or session

	c_push_data (
			an_envelope		: INTEGER;	--	C_IN CRYPT_HANDLE envelope,
			a_buffer		: POINTER;	--	C_IN void C_PTR buffer
			a_length		: INTEGER;	--	C_IN int length,
			a_bytes_copied	: POINTER	--	C_OUT int C_PTR bytesCopied
			): INTEGER is
		external "C"
		alias "cryptPushData"
		end
						 
	c_flush_data (
			an_envelope		: INTEGER	--	C_IN CRYPT_HANDLE envelope
			): INTEGER is
		external "C"
		alias "cryptFlushData"
		end
	
	c_pop_data (
			an_envelope		: INTEGER;	--	C_IN CRYPT_HANDLE envelope,
			a_buffer		: POINTER;	--	C_OUT void C_PTR buffer
			a_length		: INTEGER;	--	C_IN int length,
			a_bytes_copied	: POINTER	--	C_OUT int C_PTR bytesCopied
			): INTEGER is
		external "C"
		alias "cryptPopData"
		end

feature -- Device Functions

	-- Open and close a device

	c_device_open (
			a_device		: POINTER;	--	C_OUT CRYPT_DEVICE C_PTR device
			a_user			: INTEGER;	--	C_IN CRYPT_USER cryptUser
			a_type			: INTEGER;	--	C_IN CRYPT_DEVICE_TYPE deviceType
			a_name			: POINTER	--	C_IN C_STR name
			): INTEGER is
		external "C"
		alias "cryptDeviceOpen"
		end
						   
	c_device_close (
			a_device		: INTEGER	--	C_IN CRYPT_DEVICE device
			): INTEGER is
		external "C"
		alias "cryptDeviceClose"
		end

	-- Query a devices capabilities

	c_device_query_capability (
			a_device		: INTEGER;	--	C_IN CRYPT_DEVICE device
			an_algorithm	: INTEGER;	--	C_IN CRYPT_ALGO_TYPE cryptAlgo
			a_query			: POINTER	--	C_OUT CRYPT_QUERY_INFO C_PTR cryptQueryInfo
			): INTEGER is
		external "C"
		alias "cryptDeviceQueryCapability"
		end

	-- Create an encryption context via the device

	c_device_create_context (
			a_device		: INTEGER;	--	C_IN CRYPT_DEVICE device
			a_context		: POINTER;	--	C_OUT CRYPT_CONTEXT C_PTR cryptContext
			an_algorithm	: INTEGER	--	C_IN CRYPT_ALGO_TYPE cryptAlgo
			): INTEGER is
		external "C"
		alias "cryptDeviceCreateContext"
		end

feature -- User Management Functions

	-- Log on and off (create/destroy a user object)

	c_login (
			a_user		: POINTER;	--	C_OUT CRYPT_USER C_PTR user
			a_name		: POINTER;	--	C_IN C_STR name,
			a_password	: POINTER	--	C_IN C_STR password
			): INTEGER is
		external "C"
		alias "cryptLogin"
		end
					  
	c_logout (
			a_user		: INTEGER	--	C_IN CRYPT_USER user
			): INTEGER is
		external "C"
		alias "cryptLogout"
		end


feature -- User Interface Functions (Win32 ONLY)

	-- User interface functions, only available under Win32

--	a_ui_generate_key (
--				--	C_IN CRYPT_DEVICE cryptDevice,
--				--	C_OUT CRYPT_CONTEXT C_PTR cryptContext,
--				--	C_IN CRYPT_CERTIFICATE cryptCert,
--				--	C_OUT char C_PTR password,
--				--	C_IN HWND hWnd );
--			): INTEGER is
--		external "C"
--		alias "cryptUIGenerateKey"
--		end
						  
--	a_ui_display_certificate (
--				--	C_IN CRYPT_CERTIFICATE cryptCert,
--				--	C_IN HWND hWnd );
--			): INTEGER is
--		external "C"
--		alias "cryptUIDisplayCert"
--		end

feature

	c_add_certificate_extension(
			a_certificate		: INTEGER;		-- handle of certificate to extend
			an_oid				: POINTER;		-- object identifier for the extension
			a_critical_flag		: INTEGER;		-- critical flag for the extension
			an_extension		: POINTER;		-- address of the extension data
			a_length			: INTEGER		-- length of the extension data
			): INTEGER is
		external "C"
		alias "cryptAddCertExtension"
		end

	c_add_private_key(
			a_keyset			: INTEGER;		-- The keyset object handle
			a_key				: INTEGER;		-- The private key handle
			a_password			: POINTER		-- The password (char *)
			): INTEGER is
		external "C"
		alias "cryptAddPrivateKey"
		end


	c_add_random(
			a_data				: POINTER;		-- Pointer to random data area
			a_length			: INTEGER		-- Size of random data area
			): INTEGER is
		external "C"
		alias "cryptAddRandom"
		end

	c_async_cancel(
			a_handle			: INTEGER		-- Handle of object
			): INTEGER is
		external "C"
		alias "cryptAsyncCancel"
		end

	c_async_query(
			a_handle			: INTEGER
			): INTEGER is
		external "C"
		alias "cryptAsyncQuery"
		end

	c_caa_add_item(
			a_keyset			: INTEGER;
			a_certificate		: INTEGER
			): INTEGER is
		external "C"
		alias "cryptCAAAddItem"
		end

	c_ca_cert_management(
			a_crypt_certificate	: POINTER;
			an_action			: INTEGER;
			a_keyset			: INTEGER;
			a_ca_key			: INTEGER;
			a_cert_request		: INTEGER
			): INTEGER is
		external "C"
		alias "cryptCACertManagament"
		end

	c_ca_get_item(
			a_keyset			: INTEGER;		-- Certificate store
			a_certificate		: POINTER;
			a_cert_type			: INTEGER;
			a_key_id_type		: INTEGER;
			a_key_id			: POINTER
			): INTEGER is
		external "C"
		alias "cryptCAGetItem"
		end

	c_check_certificate(
			a_certificate		: INTEGER;
			a_handle			: INTEGER
			): INTEGER is
		external "C"
		alias "cryptCheckCert"
		end
end
	