indexing

	description: "Generate class for cryptlib constants"

	comment: "[
		Due to the heavy use of enums in cryptlib.h, is is not possible
		or appropriate to write a direct translation of the integer values
		of the C header file.
	]"

class ECRYPT_MAKE_CONSTANTS

--	inherit

--	EDP_PR

creation

	make

feature

	make is
		do
			set_class_name("ECRYPT_CONSTANTS")

			include("/data/Master/backup/cryptlib/src/cryptlib.h")
			append_head
			process_algorithms_and_codes
			process_keyset_types
			process_device_types
			process_certificate_types
			process_envelope_types
			process_session_types
			process_user_types
			process_attribute_subtypes
			
			process_error_features
			append_tail
		end

feature -- Algorithm and code types

	USE_VENDOR_ALGOS: BOOLEAN is False

	process_algorithms_and_codes is
		do
			-- Algorithms

			-- No encryption
			process_integer_feature("CRYPT_ALGO_NONE")			-- No encryption

			-- Conventional encryption
			process_integer_feature("CRYPT_ALGO_DES")			-- DES
			process_integer_feature("CRYPT_ALGO_3DES")			-- Triple DES
			process_integer_feature("CRYPT_ALGO_IDEA")			-- IDEA
			process_integer_feature("CRYPT_ALGO_CAST")			-- CAST-128
			process_integer_feature("CRYPT_ALGO_RC2")			-- RC2
			process_integer_feature("CRYPT_ALGO_RC4")			-- RC4
			process_integer_feature("CRYPT_ALGO_RC5")			-- RC5
			process_integer_feature("CRYPT_ALGO_AES")			-- AES
			process_integer_feature("CRYPT_ALGO_BLOWFISH")		-- Blowfish
			process_integer_feature("CRYPT_ALGO_SKIPJACK")		-- Skipjack

			-- Public-key encryption
			process_integer_feature("CRYPT_ALGO_DH")			-- Diffie-Hellman
			process_integer_feature("CRYPT_ALGO_RSA")			-- RSA
			process_integer_feature("CRYPT_ALGO_DSA")			-- DSA
			process_integer_feature("CRYPT_ALGO_ELGAMAL")		-- ElGamal
			process_integer_feature("CRYPT_ALGO_KEA")			-- KEA

			--  Hash algorithms
			process_integer_feature("CRYPT_ALGO_MD2")			-- MD2
			process_integer_feature("CRYPT_ALGO_MD4")			-- MD4
			process_integer_feature("CRYPT_ALGO_MD5")			-- MD5
			process_integer_feature("CRYPT_ALGO_SHA")			-- SHA/SHA1
			process_integer_feature("CRYPT_ALGO_RIPEMD160")		-- RIPE-MD 160
			process_integer_feature("CRYPT_ALGO_SHA2")			-- SHA2 (SHA-256/384/512)

			-- MAC's
			process_integer_feature("CRYPT_ALGO_HMAC_MD5")			-- HMAC-MD5
			process_integer_feature("CRYPT_ALGO_HMAC_SHA")			-- HMAC-SHA
			process_integer_feature("CRYPT_ALGO_HMAC_RIPEMD160")	-- HMAC-RIPEMD-160

			-- Vendors may want to use their own algorithms that aren't part of the
			-- general cryptlib suite.  The following values are for vendor-defined
			-- algorithms, and can be used just like the named algorithm types (it's
			-- up to the vendor to keep track of what _VENDOR1 actually corresponds
			-- to)
			if USE_VENDOR_ALGOS then
				process_integer_feature("CRYPT_ALGO_VENDOR1")
				process_integer_feature("CRYPT_ALGO_VENDOR2")
				process_integer_feature("CRYPT_ALGO_VENDOR3")
			end

			process_integer_feature("CRYPT_ALGO_LAST")				-- Last possible crypt algo value

			-- In order that we can scan through a range of algorithms with
			-- cryptQueryCapability(), we define the following boundary points for
			-- each algorithm class
			process_integer_feature("CRYPT_ALGO_FIRST_CONVENTIONAL")
			process_integer_feature("CRYPT_ALGO_LAST_CONVENTIONAL")
			process_integer_feature("CRYPT_ALGO_FIRST_PKC")
			process_integer_feature("CRYPT_ALGO_LAST_PKC")
			process_integer_feature("CRYPT_ALGO_FIRST_HASH")
			process_integer_feature("CRYPT_ALGO_LAST_HASH")
			process_integer_feature("CRYPT_ALGO_FIRST_MAC")
			process_integer_feature("CRYPT_ALGO_LAST_MAC")

			-- Block cipher modes
			process_integer_feature("CRYPT_MODE_NONE")		-- No encryption mode
			process_integer_feature("CRYPT_MODE_ECB")		-- ECB
			process_integer_feature("CRYPT_MODE_CBC")		-- CBC
			process_integer_feature("CRYPT_MODE_CFB")		-- CFB
			process_integer_feature("CRYPT_MODE_OFB")		-- OFB
			process_integer_feature("CRYPT_MODE_LAST")		-- Last possible crypt mode value
		end

feature -- Keyset type

	process_keyset_types is
			-- Keyset subtypes
		do
			process_integer_feature("CRYPT_KEYSET_NONE")			-- No keyset type
			process_integer_feature("CRYPT_KEYSET_FILE")			-- Generic flat file keyset
			process_integer_feature("CRYPT_KEYSET_HTTP")			-- Web page containing cert/CRL
			process_integer_feature("CRYPT_KEYSET_LDAP")			-- LDAP directory service
			process_integer_feature("CRYPT_KEYSET_ODBC")			-- Generic ODBC interface
			process_integer_feature("CRYPT_KEYSET_DATABASE")		-- Generic RDBMS interface
			process_integer_feature("CRYPT_KEYSET_PLUGIN")			-- Generic database plugin
			process_integer_feature("CRYPT_KEYSET_ODBC_STORE")		-- ODBC certificate store
			process_integer_feature("CRYPT_KEYSET_DATABASE_STORE")	-- Database certificate store
			process_integer_feature("CRYPT_KEYSET_PLUGIN_STORE")	-- Database plugin certificate store
			process_integer_feature("CRYPT_KEYSET_LAST")			-- Last possible keyset type
		end

feature -- Device types

	process_device_types is
			-- Crypto device types
		do
			process_integer_feature("CRYPT_DEVICE_NONE")			-- No crypto device
			process_integer_feature("CRYPT_DEVICE_FORTEZZA")		-- Fortezza card
			process_integer_feature("CRYPT_DEVICE_PKCS11")			-- PKCS #11 crypto token
			process_integer_feature("CRYPT_DEVICE_CRYPTOAPI")		-- Microsoft CryptoAPI
			process_integer_feature("CRYPT_DEVICE_LAST")			-- Last possible crypto device type
		end

feature -- Certificate types

	process_certificate_types is 
			-- Certificate subtypes
		do
			process_integer_feature("CRYPT_CERTTYPE_NONE")					-- No certificate type
			process_integer_feature("CRYPT_CERTTYPE_CERTIFICATE")			-- Certificate
			process_integer_feature("CRYPT_CERTTYPE_ATTRIBUTE_CERT")		-- Attribute certificate
			process_integer_feature("CRYPT_CERTTYPE_CERTCHAIN")				-- PKCS #7 certificate chain
			process_integer_feature("CRYPT_CERTTYPE_CERTREQUEST")			-- PKCS #10 certification request
			process_integer_feature("CRYPT_CERTTYPE_REQUEST_CERT")			-- CRMF certification request
			process_integer_feature("CRYPT_CERTTYPE_REQUEST_REVOCATION")	-- CRMF revocation request
			process_integer_feature("CRYPT_CERTTYPE_CRL")					-- CRL
			process_integer_feature("CRYPT_CERTTYPE_CMS_ATTRIBUTES")		-- CMS attributes
			process_integer_feature("CRYPT_CERTTYPE_RTCS_REQUEST")			-- RTCS request
			process_integer_feature("CRYPT_CERTTYPE_RTCS_RESPONSE")			-- RTCS response
			process_integer_feature("CRYPT_CERTTYPE_OCSP_REQUEST")			-- OCSP request
			process_integer_feature("CRYPT_CERTTYPE_OCSP_RESPONSE")			-- OCSP response
			process_integer_feature("CRYPT_CERTTYPE_PKIUSER")				-- PKI user information
			process_integer_feature("CRYPT_CERTTYPE_LAST")					-- Last possible cert.type
		end

feature -- Envelope/data types

	process_envelope_types is
			-- Envelope/data format subtypes
		do
			process_integer_feature("CRYPT_FORMAT_NONE")			-- No format type
			process_integer_feature("CRYPT_FORMAT_AUTO")			-- Deenv, auto-determine type
			process_integer_feature("CRYPT_FORMAT_CRYPTLIB")		-- cryptlib native format
			process_integer_feature("CRYPT_FORMAT_CMS")				-- PKCS #7 / CMS / S/MIME fmt.
			process_integer_feature("CRYPT_FORMAT_PKCS7")
			process_integer_feature("CRYPT_FORMAT_SMIME")			-- As CMS with MSG-style behaviour
			process_integer_feature("CRYPT_FORMAT_PGP")				-- PGP format
			process_integer_feature("CRYPT_FORMAT_LAST")			-- Last possible format type
		end

feature -- Session types

	process_session_types is
		do
			process_integer_feature("CRYPT_SESSION_NONE")				-- No session type
			process_integer_feature("CRYPT_SESSION_SSH")				-- SSH
			process_integer_feature("CRYPT_SESSION_SSH_SERVER")			-- SSH server
			process_integer_feature("CRYPT_SESSION_SSL")				-- SSL/TLS
			process_integer_feature("CRYPT_SESSION_SSL_SERVER")			-- SSL/TLS server
			process_integer_feature("CRYPT_SESSION_RTCS")				-- RTCS
			process_integer_feature("CRYPT_SESSION_RTCS_SERVER")		-- RTCS server
			process_integer_feature("CRYPT_SESSION_OCSP")				-- OCSP
			process_integer_feature("CRYPT_SESSION_OCSP_SERVER")		-- OCSP server
			process_integer_feature("CRYPT_SESSION_TSP")				-- TSP
			process_integer_feature("CRYPT_SESSION_TSP_SERVER")			-- TSP server
			process_integer_feature("CRYPT_SESSION_CMP")				-- CMP
			process_integer_feature("CRYPT_SESSION_CMP_SERVER")			-- CMP server
			process_integer_feature("CRYPT_SESSION_SCEP")				-- SCEP
			process_integer_feature("CRYPT_SESSION_SCEP_SERVER")		-- SCEP server
			process_integer_feature("CRYPT_SESSION_CERTSTORE_SERVER")	-- HTTP cert store interface
			process_integer_feature("CRYPT_SESSION_LAST")				-- Last possible session type
		end

feature -- User types

	process_user_types is
		do
			process_integer_feature("CRYPT_USER_NONE")				-- No user type
			process_integer_feature("CRYPT_USER_NORMAL")			-- Normal user
			process_integer_feature("CRYPT_USER_SO")				-- Security officer
			process_integer_feature("CRYPT_USER_CA")				-- CA user
			process_integer_feature("CRYPT_USER_LAST")				-- Last possible user type
		end

feature -- Attribute types

	process_attribute_types is
		do

			-- Attribute types.  These are arranged in the following order:

			--	PROPERTY	- Object property
			--	ATTRIBUTE	- Generic attributes
			--	OPTION		- Global or object-specific config.option
			--	CTXINFO		- Context-specific attribute
			--	CERTINFO	- Certificate-specific attribute
			--	KEYINFO		- Keyset-specific attribute
			--	DEVINFO		- Device-specific attribute
			--	ENVINFO		- Envelope-specific attribute
			--	SESSINFO	- Session-specific attribute
			--	USERINFO	- User-specific attribute */

--#####################################################################################################################

			process_integer_feature("CRYPT_ATTRIBUTE_NONE")				-- Non-value

			--********************
			-- Object attributes
			--********************

			-- Object properties
			process_integer_feature("CRYPT_PROPERTY_HIGHSECURITY")			-- Owned+non-forwardcount+locked
			process_integer_feature("CRYPT_PROPERTY_OWNER")					-- Object owner
			process_integer_feature("CRYPT_PROPERTY_FORWARDCOUNT")			-- No.of times object can be forwarded
			process_integer_feature("CRYPT_PROPERTY_LOCKED")				-- Whether properties can be chged/read
			process_integer_feature("CRYPT_PROPERTY_USAGECOUNT")			-- Usage count before object expires
			process_integer_feature("CRYPT_PROPERTY_NONEXPORTABLE")			-- Whether key is nonexp.from context

			-- Extended error information
			process_integer_feature("CRYPT_ATTRIBUTE_ERRORTYPE")			-- Type of last error
			process_integer_feature("CRYPT_ATTRIBUTE_ERRORLOCUS")			-- Locus of last error
			process_integer_feature("CRYPT_ATTRIBUTE_INT_ERRORCODE")		-- Low-level software-specific
			process_integer_feature("CRYPT_ATTRIBUTE_INT_ERRORMESSAGE") 	--   error code and message

			-- Generic information
			process_integer_feature("CRYPT_ATTRIBUTE_CURRENT_GROUP")		-- Cursor mgt: Group in attribute list
			process_integer_feature("CRYPT_ATTRIBUTE_CURRENT")				-- Cursor mgt: Entry in attribute list
			process_integer_feature("CRYPT_ATTRIBUTE_CURRENT_INSTANCE")		-- Cursor mgt: Instance in attribute list
			process_integer_feature("CRYPT_ATTRIBUTE_BUFFERSIZE")			-- Internal data buffer size

			--***************************
			-- Configuration attributes
			--***************************

			-- cryptlib information (read-only)
			process_integer_feature("CRYPT_OPTION_INFO_DESCRIPTION")		-- Text description
			process_integer_feature("CRYPT_OPTION_INFO_COPYRIGHT")			-- Copyright notice
			process_integer_feature("CRYPT_OPTION_INFO_MAJORVERSION")		-- Major release version
			process_integer_feature("CRYPT_OPTION_INFO_MINORVERSION")		-- Minor release version
			process_integer_feature("CRYPT_OPTION_INFO_STEPPING")			-- Release stepping

			-- Encryption options
			process_integer_feature("CRYPT_OPTION_ENCR_ALGO")				-- Encryption algorithm
			process_integer_feature("CRYPT_OPTION_ENCR_HASH")				-- Hash algorithm
			process_integer_feature("CRYPT_OPTION_ENCR_MAC")				-- MAC algorithm

			-- PKC options
			process_integer_feature("CRYPT_OPTION_PKC_ALGO")				-- Public-key encryption algorithm
			process_integer_feature("CRYPT_OPTION_PKC_KEYSIZE")				-- Public-key encryption key size

			-- Signature options
			process_integer_feature("CRYPT_OPTION_SIG_ALGO")				-- Signature algorithm
			process_integer_feature("CRYPT_OPTION_SIG_KEYSIZE")				-- Signature keysize

			-- Keying options
			process_integer_feature("CRYPT_OPTION_KEYING_ALGO")				-- Key processing algorithm
			process_integer_feature("CRYPT_OPTION_KEYING_ITERATIONS")		-- Key processing iterations

			-- Certificate options
			process_integer_feature("CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES")	-- Whether to sign unrecog.attrs
			process_integer_feature("CRYPT_OPTION_CERT_VALIDITY")					-- Certificate validity period
			process_integer_feature("CRYPT_OPTION_CERT_UPDATEINTERVAL")				-- CRL update interval
			process_integer_feature("CRYPT_OPTION_CERT_COMPLIANCELEVEL")			-- PKIX compliance level for cert chks.*/
			process_integer_feature("CRYPT_OPTION_CERT_REQUIREPOLICY")				-- Whether explicit policy req'd for certs

			-- CMS/SMIME options
			process_integer_feature("CRYPT_OPTION_CMS_DEFAULTATTRIBUTES")			-- Add default CMS attributes
			process_integer_feature("CRYPT_OPTION_SMIME_DEFAULTATTRIBUTES")

			-- LDAP keyset options
			process_integer_feature("CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS")			-- Object class
			process_integer_feature("CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE")			-- Object type to fetch
			process_integer_feature("CRYPT_OPTION_KEYS_LDAP_FILTER")				-- Query filter
			process_integer_feature("CRYPT_OPTION_KEYS_LDAP_CACERTNAME")			-- CA certificate attribute name
			process_integer_feature("CRYPT_OPTION_KEYS_LDAP_CERTNAME")				-- Certificate attribute name
			process_integer_feature("CRYPT_OPTION_KEYS_LDAP_CRLNAME")				-- CRL attribute name
			process_integer_feature("CRYPT_OPTION_KEYS_LDAP_EMAILNAME")				-- Email attribute name

			-- Crypto device options
			process_integer_feature("CRYPT_OPTION_DEVICE_PKCS11_DVR01")				-- Name of first PKCS #11 driver
			process_integer_feature("CRYPT_OPTION_DEVICE_PKCS11_DVR02")				-- Name of second PKCS #11 driver
			process_integer_feature("CRYPT_OPTION_DEVICE_PKCS11_DVR03")				-- Name of third PKCS #11 driver
			process_integer_feature("CRYPT_OPTION_DEVICE_PKCS11_DVR04")				-- Name of fourth PKCS #11 driver
			process_integer_feature("CRYPT_OPTION_DEVICE_PKCS11_DVR05")				-- Name of fifth PKCS #11 driver
			process_integer_feature("CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY")		-- Use only hardware mechanisms

			-- Network access options
			process_integer_feature("CRYPT_OPTION_NET_SOCKS_SERVER")				-- Socks server name
			process_integer_feature("CRYPT_OPTION_NET_SOCKS_USERNAME")				-- Socks user name
			process_integer_feature("CRYPT_OPTION_NET_HTTP_PROXY")					-- Web proxy server
			process_integer_feature("CRYPT_OPTION_NET_CONNECTTIMEOUT")				-- Timeout for network connection setup
			process_integer_feature("CRYPT_OPTION_NET_READTIMEOUT")					-- Timeout for network reads
			process_integer_feature("CRYPT_OPTION_NET_WRITETIMEOUT")				-- Timeout for network writes

			-- Miscellaneous options
			process_integer_feature("CRYPT_OPTION_MISC_ASYNCINIT")					-- Whether to init cryptlib async'ly
			process_integer_feature("CRYPT_OPTION_MISC_SIDECHANNELPROTECTION")		-- Protect against side-channel attacks

			-- cryptlib state information
			process_integer_feature("CRYPT_OPTION_CONFIGCHANGED")					-- Whether in-mem.opts match on-disk ones
			process_integer_feature("CRYPT_OPTION_SELFTESTOK")						-- Whether self-test was completed and OK

			--*********************
			-- Context attributes
			--*********************

			-- Algorithm and mode information
			process_integer_feature("CRYPT_CTXINFO_ALGO")				-- Algorithm
			process_integer_feature("CRYPT_CTXINFO_MODE")				-- Mode
			process_integer_feature("CRYPT_CTXINFO_NAME_ALGO")			-- Algorithm name
			process_integer_feature("CRYPT_CTXINFO_NAME_MODE")			-- Mode name
			process_integer_feature("CRYPT_CTXINFO_KEYSIZE")			-- Key size in bytes
			process_integer_feature("CRYPT_CTXINFO_BLOCKSIZE")			-- Block size
			process_integer_feature("CRYPT_CTXINFO_IVSIZE")				-- IV size
			process_integer_feature("CRYPT_CTXINFO_KEYING_ALGO")		-- Key processing algorithm
			process_integer_feature("CRYPT_CTXINFO_KEYING_ITERATIONS")	-- Key processing iterations
			process_integer_feature("CRYPT_CTXINFO_KEYING_SALT")		-- Key processing salt
			process_integer_feature("CRYPT_CTXINFO_KEYING_VALUE")		-- Value used to derive key

			-- State information
			process_integer_feature("CRYPT_CTXINFO_KEY")				-- Key
			process_integer_feature("CRYPT_CTXINFO_KEY_COMPONENTS")		-- Public-key components
			process_integer_feature("CRYPT_CTXINFO_IV")					-- IV
			process_integer_feature("CRYPT_CTXINFO_HASHVALUE")			-- Hash value

			-- Misc.information
			process_integer_feature("CRYPT_CTXINFO_LABEL")				-- Label for private/secret key

			--*************************
			-- Certificate attributes
			--*************************

			--	Because there are so many cert attributes, we break them down into
			--	blocks to minimise the number of values that change if a new one is
			--	added halfway through

			-- Pseudo-information on a cert object or meta-information which is used
			-- to control the way that a cert object is processed
			process_integer_feature("CRYPT_CERTINFO_SELFSIGNED")			-- Cert is self-signed
			process_integer_feature("CRYPT_CERTINFO_IMMUTABLE")				-- Cert is signed and immutable
			process_integer_feature("CRYPT_CERTINFO_XYZZY")					-- Cert is a magic just-works cert
			process_integer_feature("CRYPT_CERTINFO_CERTTYPE")				-- Certificate object type
			process_integer_feature("CRYPT_CERTINFO_FINGERPRINT")			-- Certificate fingerprints
			process_integer_feature("CRYPT_CERTINFO_FINGERPRINT_MD5")
			process_integer_feature("CRYPT_CERTINFO_FINGERPRINT_SHA")
			process_integer_feature("CRYPT_CERTINFO_CURRENT_CERTIFICATE")	-- Cursor mgt: Rel.pos in chain/CRL/OCSP
--	#if 1	-- To be removed in cryptlib 3.2
			process_integer_feature("CRYPT_CERTINFO_CURRENT_EXTENSION")		-- Cursor mgt: Rel.pos.or abs.extension
			process_integer_feature("CRYPT_CERTINFO_CURRENT_FIELD")			-- Cursor mgt: Rel.pos.or abs.field in ext
			process_integer_feature("CRYPT_CERTINFO_CURRENT_COMPONENT")		-- Cursor mgt: Rel.pos in multival.field
--	#endif -- 1
			process_integer_feature("CRYPT_CERTINFO_TRUSTED_USAGE")			-- Usage that cert is trusted for
			process_integer_feature("CRYPT_CERTINFO_TRUSTED_IMPLICIT")		-- Whether cert is implicitly trusted
			process_integer_feature("CRYPT_CERTINFO_SIGNATURELEVEL")		-- Amount of detail to include in sigs.*/

			-- General certificate object information
			process_integer_feature("CRYPT_CERTINFO_VERSION")				-- Cert.format version
			process_integer_feature("CRYPT_CERTINFO_SERIALNUMBER")			-- Serial number
			process_integer_feature("CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO")	-- Public key
			process_integer_feature("CRYPT_CERTINFO_CERTIFICATE")			-- User certificate
			process_integer_feature("CRYPT_CERTINFO_USERCERTIFICATE")
			process_integer_feature("CRYPT_CERTINFO_CACERTIFICATE")			-- CA certificate
			process_integer_feature("CRYPT_CERTINFO_ISSUERNAME")			-- Issuer DN
			process_integer_feature("CRYPT_CERTINFO_VALIDFROM")				-- Cert valid-from time
			process_integer_feature("CRYPT_CERTINFO_VALIDTO")				-- Cert valid-to time
			process_integer_feature("CRYPT_CERTINFO_SUBJECTNAME")			-- Subject DN
			process_integer_feature("CRYPT_CERTINFO_ISSUERUNIQUEID")		-- Issuer unique ID
			process_integer_feature("CRYPT_CERTINFO_SUBJECTUNIQUEID")		-- Subject unique ID
			process_integer_feature("CRYPT_CERTINFO_CERTREQUEST")			-- Cert.request (DN + public key)
			process_integer_feature("CRYPT_CERTINFO_THISUPDATE")			-- CRL/OCSP current-update time
			process_integer_feature("CRYPT_CERTINFO_NEXTUPDATE")			-- CRL/OCSP next-update time
			process_integer_feature("CRYPT_CERTINFO_REVOCATIONDATE")		-- CRL/OCSP cert-revocation time
			process_integer_feature("CRYPT_CERTINFO_REVOCATIONSTATUS")		-- OCSP revocation status
			process_integer_feature("CRYPT_CERTINFO_CERTSTATUS")			-- RTCS certificate status
			process_integer_feature("CRYPT_CERTINFO_DN")					-- Currently selected DN in string form
			process_integer_feature("CRYPT_CERTINFO_PKIUSER_ID")			-- PKI user ID
			process_integer_feature("CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD")	-- PKI user issue password
			process_integer_feature("CRYPT_CERTINFO_PKIUSER_REVPASSWORD")	-- PKI user revocation password

			--	X.520 Distinguished Name components.  This is a composite field, the
			--	DN to be manipulated is selected through the addition of a
			--	pseudocomponent, and then one of the following is used to access the
			--	DN components directly
			process_integer_feature("CRYPT_CERTINFO_COUNTRYNAME = CRYPT_CERTINFO_FIRST + 100")	-- countryName
			process_integer_feature("CRYPT_CERTINFO_STATEORPROVINCENAME")			-- stateOrProvinceName
			process_integer_feature("CRYPT_CERTINFO_LOCALITYNAME")				-- localityName
			process_integer_feature("CRYPT_CERTINFO_ORGANIZATIONNAME")			-- organizationName
			process_integer_feature("CRYPT_CERTINFO_ORGANISATIONNAME")
			process_integer_feature("CRYPT_CERTINFO_ORGANIZATIONALUNITNAME")	-- organizationalUnitName
			process_integer_feature("CRYPT_CERTINFO_ORGANISATIONALUNITNAME")
			process_integer_feature("CRYPT_CERTINFO_COMMONNAME")				-- commonName

			-- 	X.509 General Name components.  These are handled in the same way as
			--	the DN composite field, with the current GeneralName being selected by
			--	a pseudo-component after which the individual components can be
			--	modified through one of the following
			process_integer_feature("CRYPT_CERTINFO_OTHERNAME_TYPEID")			-- otherName.typeID
			process_integer_feature("CRYPT_CERTINFO_OTHERNAME_VALUE")			-- otherName.value
			process_integer_feature("CRYPT_CERTINFO_RFC822NAME")				-- rfc822Name
			process_integer_feature("CRYPT_CERTINFO_EMAIL")
			process_integer_feature("CRYPT_CERTINFO_DNSNAME")					-- dNSName
--	#if 0	-- Not supported yet, these are never used in practice and have an
			-- insane internal structure
			process_integer_feature("CRYPT_CERTINFO_X400ADDRESS")				-- x400Address
--	#endif -- 0
			process_integer_feature("CRYPT_CERTINFO_DIRECTORYNAME")				-- directoryName
			process_integer_feature("CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER")	-- ediPartyName.nameAssigner
			process_integer_feature("CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME")	-- ediPartyName.partyName
			process_integer_feature("CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER")	-- uniformResourceIdentifier
			process_integer_feature("CRYPT_CERTINFO_IPADDRESS")					-- iPAddress
			process_integer_feature("CRYPT_CERTINFO_REGISTEREDID")				-- registeredID

			-- X.509 certificate extensions.  Although it would be nicer to use names
			-- that match the extensions more closely (e.g.
			-- CRYPT_CERTINFO_BASICCONSTRAINTS_PATHLENCONSTRAINT), these exceed the
			-- 32-character ANSI minimum length for unique names, and get really
			-- hairy once you get into the weird policy constraints extensions whose
			-- names wrap around the screen about three times.

			-- The following values are defined in OID order, this isn't absolutely
			-- necessary but saves an extra layer of processing when encoding them

			-- 1 2 840 113549 1 9 7 challengePassword.  This is here even though it's
			-- a CMS attribute because SCEP stuffs it into PKCS #10 requests
			process_integer_feature("CRYPT_CERTINFO_CHALLENGEPASSWORD")

			-- 1 3 6 1 4 1 3029 3 1 4 cRLExtReason
			process_integer_feature("CRYPT_CERTINFO_CRLEXTREASON")

			-- 1 3 6 1 4 1 3029 3 1 5 keyFeatures
			process_integer_feature("CRYPT_CERTINFO_KEYFEATURES")

			-- 1 3 6 1 5 5 7 1 1 authorityInfoAccess
			process_integer_feature("CRYPT_CERTINFO_AUTHORITYINFOACCESS")
			process_integer_feature("CRYPT_CERTINFO_AUTHORITYINFO_RTCS")			-- accessDescription.accessLocation
			process_integer_feature("CRYPT_CERTINFO_AUTHORITYINFO_OCSP")			-- accessDescription.accessLocation
			process_integer_feature("CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS")		-- accessDescription.accessLocation
			process_integer_feature("CRYPT_CERTINFO_AUTHORITYINFO_CERTSTORE")		-- accessDescription.accessLocation
			process_integer_feature("CRYPT_CERTINFO_AUTHORITYINFO_CRLS")			-- accessDescription.accessLocation

			-- 1 3 6 1 5 5 7 1 2 biometricInfo
			process_integer_feature("CRYPT_CERTINFO_BIOMETRICINFO")
			process_integer_feature("CRYPT_CERTINFO_BIOMETRICINFO_TYPE")			-- biometricData.typeOfData
			process_integer_feature("CRYPT_CERTINFO_BIOMETRICINFO_HASHALGO")		-- biometricData.hashAlgorithm
			process_integer_feature("CRYPT_CERTINFO_BIOMETRICINFO_HASH")			-- biometricData.dataHash
			process_integer_feature("CRYPT_CERTINFO_BIOMETRICINFO_URL")				-- biometricData.sourceDataUri

			-- 1 3 6 1 5 5 7 1 3 qcStatements
			process_integer_feature("CRYPT_CERTINFO_QCSTATEMENT")
			process_integer_feature("CRYPT_CERTINFO_QCSTATEMENT_SEMANTICS")
							-- qcStatement.statementInfo.semanticsIdentifier
			process_integer_feature("CRYPT_CERTINFO_QCSTATEMENT_REGISTRATIONAUTHORITY")
							-- qcStatement.statementInfo.nameRegistrationAuthorities

			-- 1 3 6 1 5 5 7 48 1 2 ocspNonce
			process_integer_feature("CRYPT_CERTINFO_OCSP_NONCE")					-- nonce

			-- 1 3 6 1 5 5 7 48 1 4 ocspAcceptableResponses
			process_integer_feature("CRYPT_CERTINFO_OCSP_RESPONSE")
			process_integer_feature("CRYPT_CERTINFO_OCSP_RESPONSE_OCSP")			-- OCSP standard response

			-- 1 3 6 1 5 5 7 48 1 5 ocspNoCheck
			process_integer_feature("CRYPT_CERTINFO_OCSP_NOCHECK")

			-- 1 3 6 1 5 5 7 48 1 6 ocspArchiveCutoff
			process_integer_feature("CRYPT_CERTINFO_OCSP_ARCHIVECUTOFF")

			-- 1 3 6 1 5 5 7 48 1 11 subjectInfoAccess
			process_integer_feature("CRYPT_CERTINFO_SUBJECTINFOACCESS")
			process_integer_feature("CRYPT_CERTINFO_SUBJECTINFO_CAREPOSITORY")		-- accessDescription.accessLocation
			process_integer_feature("CRYPT_CERTINFO_SUBJECTINFO_TIMESTAMPING")		-- accessDescription.accessLocation

			-- 1 3 36 8 3 1 siggDateOfCertGen
			process_integer_feature("CRYPT_CERTINFO_SIGG_DATEOFCERTGEN")

			-- 1 3 36 8 3 2 siggProcuration
			process_integer_feature("CRYPT_CERTINFO_SIGG_PROCURATION")
			process_integer_feature("CRYPT_CERTINFO_SIGG_PROCURE_COUNTRY")				-- country
			process_integer_feature("CRYPT_CERTINFO_SIGG_PROCURE_TYPEOFSUBSTITUTION")	-- typeOfSubstitution
			process_integer_feature("CRYPT_CERTINFO_SIGG_PROCURE_SIGNINGFOR")			-- signingFor.thirdPerson

			-- 1 3 36 8 3 4 siggMonetaryLimit
			process_integer_feature("CRYPT_CERTINFO_SIGG_MONETARYLIMIT")
			process_integer_feature("CRYPT_CERTINFO_SIGG_MONETARY_CURRENCY")	-- currency
			process_integer_feature("CRYPT_CERTINFO_SIGG_MONETARY_AMOUNT")	-- amount
			process_integer_feature("CRYPT_CERTINFO_SIGG_MONETARY_EXPONENT")	-- exponent

			-- 1 3 36 8 3 8 siggRestriction
			process_integer_feature("CRYPT_CERTINFO_SIGG_RESTRICTION")

			-- 1 3 101 1 4 1 strongExtranet
			process_integer_feature("CRYPT_CERTINFO_STRONGEXTRANET")
			process_integer_feature("CRYPT_CERTINFO_STRONGEXTRANET_ZONE")		-- sxNetIDList.sxNetID.zone
			process_integer_feature("CRYPT_CERTINFO_STRONGEXTRANET_ID")			-- sxNetIDList.sxNetID.id

			-- 2 5 29 9 subjectDirectoryAttributes
			process_integer_feature("CRYPT_CERTINFO_SUBJECTDIRECTORYATTRIBUTES")
			process_integer_feature("CRYPT_CERTINFO_SUBJECTDIR_TYPE")			-- attribute.type
			process_integer_feature("CRYPT_CERTINFO_SUBJECTDIR_VALUES")			-- attribute.values

			-- 2 5 29 14 subjectKeyIdentifier
			process_integer_feature("CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER")

			-- 2 5 29 15 keyUsage
			process_integer_feature("CRYPT_CERTINFO_KEYUSAGE")

			-- 2 5 29 16 privateKeyUsagePeriod
			process_integer_feature("CRYPT_CERTINFO_PRIVATEKEYUSAGEPERIOD")
			process_integer_feature("CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE")		-- notBefore
			process_integer_feature("CRYPT_CERTINFO_PRIVATEKEY_NOTAFTER")		-- notAfter

			-- 2 5 29 17 subjectAltName
			process_integer_feature("CRYPT_CERTINFO_SUBJECTALTNAME")

			-- 2 5 29 18 issuerAltName
			process_integer_feature("CRYPT_CERTINFO_ISSUERALTNAME")

			-- 2 5 29 19 basicConstraints
			process_integer_feature("CRYPT_CERTINFO_BASICCONSTRAINTS")
			process_integer_feature("CRYPT_CERTINFO_CA")						-- cA
			process_integer_feature("CRYPT_CERTINFO_AUTHORITY")
			process_integer_feature("CRYPT_CERTINFO_PATHLENCONSTRAINT")		-- pathLenConstraint

			-- 2 5 29 20 cRLNumber
			process_integer_feature("CRYPT_CERTINFO_CRLNUMBER")

			-- 2 5 29 21 cRLReason
			process_integer_feature("CRYPT_CERTINFO_CRLREASON")

			-- 2 5 29 23 holdInstructionCode
			process_integer_feature("CRYPT_CERTINFO_HOLDINSTRUCTIONCODE")

			-- 2 5 29 24 invalidityDate
			process_integer_feature("CRYPT_CERTINFO_INVALIDITYDATE")

			-- 2 5 29 27 deltaCRLIndicator
			process_integer_feature("CRYPT_CERTINFO_DELTACRLINDICATOR")

			-- 2 5 29 28 issuingDistributionPoint
			process_integer_feature("CRYPT_CERTINFO_ISSUINGDISTRIBUTIONPOINT")
			process_integer_feature("CRYPT_CERTINFO_ISSUINGDIST_FULLNAME")	-- distributionPointName.fullName
			process_integer_feature("CRYPT_CERTINFO_ISSUINGDIST_USERCERTSONLY")	-- onlyContainsUserCerts
			process_integer_feature("CRYPT_CERTINFO_ISSUINGDIST_CACERTSONLY")	-- onlyContainsCACerts
			process_integer_feature("CRYPT_CERTINFO_ISSUINGDIST_SOMEREASONSONLY")	-- onlySomeReasons
			process_integer_feature("CRYPT_CERTINFO_ISSUINGDIST_INDIRECTCRL")	-- indirectCRL

			-- 2 5 29 29 certificateIssuer
			process_integer_feature("CRYPT_CERTINFO_CERTIFICATEISSUER")

			-- 2 5 29 30 nameConstraints
			process_integer_feature("CRYPT_CERTINFO_NAMECONSTRAINTS")
			process_integer_feature("CRYPT_CERTINFO_PERMITTEDSUBTREES")		-- permittedSubtrees
			process_integer_feature("CRYPT_CERTINFO_EXCLUDEDSUBTREES")		-- excludedSubtrees

			-- 2 5 29 31 cRLDistributionPoint
			process_integer_feature("CRYPT_CERTINFO_CRLDISTRIBUTIONPOINT")
			process_integer_feature("CRYPT_CERTINFO_CRLDIST_FULLNAME")		-- distributionPointName.fullName
			process_integer_feature("CRYPT_CERTINFO_CRLDIST_REASONS")			-- reasons
			process_integer_feature("CRYPT_CERTINFO_CRLDIST_CRLISSUER")		-- cRLIssuer

			-- 2 5 29 32 certificatePolicies
			process_integer_feature("CRYPT_CERTINFO_CERTIFICATEPOLICIES")
			process_integer_feature("CRYPT_CERTINFO_CERTPOLICYID")		-- policyInformation.policyIdentifier
			process_integer_feature("CRYPT_CERTINFO_CERTPOLICY_CPSURI")
				-- policyInformation.policyQualifiers.qualifier.cPSuri
			process_integer_feature("CRYPT_CERTINFO_CERTPOLICY_ORGANIZATION")
				-- policyInformation.policyQualifiers.qualifier.userNotice.noticeRef.organization
			process_integer_feature("CRYPT_CERTINFO_CERTPOLICY_NOTICENUMBERS")
				-- policyInformation.policyQualifiers.qualifier.userNotice.noticeRef.noticeNumbers
			process_integer_feature("CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT")
				-- policyInformation.policyQualifiers.qualifier.userNotice.explicitText

			-- 2 5 29 33 policyMappings
			process_integer_feature("CRYPT_CERTINFO_POLICYMAPPINGS")
			process_integer_feature("CRYPT_CERTINFO_ISSUERDOMAINPOLICY")	-- policyMappings.issuerDomainPolicy
			process_integer_feature("CRYPT_CERTINFO_SUBJECTDOMAINPOLICY")	-- policyMappings.subjectDomainPolicy

			-- 2 5 29 35 authorityKeyIdentifier
			process_integer_feature("CRYPT_CERTINFO_AUTHORITYKEYIDENTIFIER")
			process_integer_feature("CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER")	-- keyIdentifier
			process_integer_feature("CRYPT_CERTINFO_AUTHORITY_CERTISSUER")	-- authorityCertIssuer
			process_integer_feature("CRYPT_CERTINFO_AUTHORITY_CERTSERIALNUMBER")	-- authorityCertSerialNumber

			-- 2 5 29 36 policyConstraints
			process_integer_feature("CRYPT_CERTINFO_POLICYCONSTRAINTS")
			process_integer_feature("CRYPT_CERTINFO_REQUIREEXPLICITPOLICY")	-- policyConstraints.requireExplicitPolicy
			process_integer_feature("CRYPT_CERTINFO_INHIBITPOLICYMAPPING")	-- policyConstraints.inhibitPolicyMapping

			-- 2 5 29 37 extKeyUsage
			process_integer_feature("CRYPT_CERTINFO_EXTKEYUSAGE")
			process_integer_feature("CRYPT_CERTINFO_EXTKEY_MS_INDIVIDUALCODESIGNING")	-- individualCodeSigning
			process_integer_feature("CRYPT_CERTINFO_EXTKEY_MS_COMMERCIALCODESIGNING")	-- commercialCodeSigning
			process_integer_feature("CRYPT_CERTINFO_EXTKEY_MS_CERTTRUSTLISTSIGNING")		-- certTrustListSigning
			process_integer_feature("CRYPT_CERTINFO_EXTKEY_MS_TIMESTAMPSIGNING")			-- timeStampSigning
			process_integer_feature("CRYPT_CERTINFO_EXTKEY_MS_SERVERGATEDCRYPTO")		-- serverGatedCrypto
			process_integer_feature("CRYPT_CERTINFO_EXTKEY_MS_ENCRYPTEDFILESYSTEM")		-- encrypedFileSystem
			process_integer_feature("CRYPT_CERTINFO_EXTKEY_SERVERAUTH")					-- serverAuth
			process_integer_feature("CRYPT_CERTINFO_EXTKEY_CLIENTAUTH")					-- clientAuth
			process_integer_feature("CRYPT_CERTINFO_EXTKEY_CODESIGNING")					-- codeSigning
			process_integer_feature("CRYPT_CERTINFO_EXTKEY_EMAILPROTECTION")				-- emailProtection
			process_integer_feature("CRYPT_CERTINFO_EXTKEY_IPSECENDSYSTEM")				-- ipsecEndSystem
			process_integer_feature("CRYPT_CERTINFO_EXTKEY_IPSECTUNNEL")					-- ipsecTunnel
			process_integer_feature("CRYPT_CERTINFO_EXTKEY_IPSECUSER")					-- ipsecUser
			process_integer_feature("CRYPT_CERTINFO_EXTKEY_TIMESTAMPING")				-- timeStamping
			process_integer_feature("CRYPT_CERTINFO_EXTKEY_OCSPSIGNING")					-- ocspSigning
			process_integer_feature("CRYPT_CERTINFO_EXTKEY_DIRECTORYSERVICE")			-- directoryService
			process_integer_feature("CRYPT_CERTINFO_EXTKEY_ANYKEYUSAGE")					-- anyExtendedKeyUsage
			process_integer_feature("CRYPT_CERTINFO_EXTKEY_NS_SERVERGATEDCRYPTO")		-- serverGatedCrypto
			process_integer_feature("CRYPT_CERTINFO_EXTKEY_VS_SERVERGATEDCRYPTO_CA")		-- serverGatedCrypto CA

			-- 2 5 29 46 freshestCRL
			process_integer_feature("CRYPT_CERTINFO_FRESHESTCRL")
			process_integer_feature("CRYPT_CERTINFO_FRESHESTCRL_FULLNAME")		-- distributionPointName.fullName
			process_integer_feature("CRYPT_CERTINFO_FRESHESTCRL_REASONS")		-- reasons
			process_integer_feature("CRYPT_CERTINFO_FRESHESTCRL_CRLISSUER")		-- cRLIssuer

			-- 2 5 29 54 inhibitAnyPolicy
			process_integer_feature("CRYPT_CERTINFO_INHIBITANYPOLICY")

			-- 2 16 840 1 113730 1 x Netscape extensions
			process_integer_feature("CRYPT_CERTINFO_NS_CERTTYPE")				-- netscape-cert-type
			process_integer_feature("CRYPT_CERTINFO_NS_BASEURL")				-- netscape-base-url
			process_integer_feature("CRYPT_CERTINFO_NS_REVOCATIONURL")			-- netscape-revocation-url
			process_integer_feature("CRYPT_CERTINFO_NS_CAREVOCATIONURL")		-- netscape-ca-revocation-url
			process_integer_feature("CRYPT_CERTINFO_NS_CERTRENEWALURL")			-- netscape-cert-renewal-url
			process_integer_feature("CRYPT_CERTINFO_NS_CAPOLICYURL")			-- netscape-ca-policy-url
			process_integer_feature("CRYPT_CERTINFO_NS_SSLSERVERNAME")			-- netscape-ssl-server-name
			process_integer_feature("CRYPT_CERTINFO_NS_COMMENT")				-- netscape-comment

			-- 2 23 42 7 0 SET hashedRootKey
			process_integer_feature("CRYPT_CERTINFO_SET_HASHEDROOTKEY")
			process_integer_feature("CRYPT_CERTINFO_SET_ROOTKEYTHUMBPRINT")		-- rootKeyThumbPrint

			-- 2 23 42 7 1 SET certificateType
			process_integer_feature("CRYPT_CERTINFO_SET_CERTIFICATETYPE")

			-- 2 23 42 7 2 SET merchantData
			process_integer_feature("CRYPT_CERTINFO_SET_MERCHANTDATA")
			process_integer_feature("CRYPT_CERTINFO_SET_MERID")					-- merID
			process_integer_feature("CRYPT_CERTINFO_SET_MERACQUIRERBIN")		-- merAcquirerBIN
			process_integer_feature("CRYPT_CERTINFO_SET_MERCHANTLANGUAGE")		-- merNames.language
			process_integer_feature("CRYPT_CERTINFO_SET_MERCHANTNAME")			-- merNames.name
			process_integer_feature("CRYPT_CERTINFO_SET_MERCHANTCITY")			-- merNames.city
			process_integer_feature("CRYPT_CERTINFO_SET_MERCHANTSTATEPROVINCE")	-- merNames.stateProvince
			process_integer_feature("CRYPT_CERTINFO_SET_MERCHANTPOSTALCODE")	-- merNames.postalCode
			process_integer_feature("CRYPT_CERTINFO_SET_MERCHANTCOUNTRYNAME")	-- merNames.countryName
			process_integer_feature("CRYPT_CERTINFO_SET_MERCOUNTRY")			-- merCountry
			process_integer_feature("CRYPT_CERTINFO_SET_MERAUTHFLAG")			-- merAuthFlag

			-- 2 23 42 7 3 SET certCardRequired
			process_integer_feature("CRYPT_CERTINFO_SET_CERTCARDREQUIRED")

			-- 2 23 42 7 4 SET tunneling
			process_integer_feature("CRYPT_CERTINFO_SET_TUNNELING")
			process_integer_feature("CRYPT_CERTINFO_SET_TUNNELLING")
			process_integer_feature("CRYPT_CERTINFO_SET_TUNNELINGFLAG")		-- tunneling
			process_integer_feature("CRYPT_CERTINFO_SET_TUNNELLINGFLAG")
			process_integer_feature("CRYPT_CERTINFO_SET_TUNNELINGALGID")		-- tunnelingAlgID
				process_integer_feature("CRYPT_CERTINFO_SET_TUNNELLINGALGID = CRYPT_CERTINFO_SET_TUNNELINGALGID")

			-- S/MIME attributes

			-- 1 2 840 113549 1 9 3 contentType
			process_integer_feature("CRYPT_CERTINFO_CMS_CONTENTTYPE")

			-- 1 2 840 113549 1 9 4 messageDigest
			process_integer_feature("CRYPT_CERTINFO_CMS_MESSAGEDIGEST")

			-- 1 2 840 113549 1 9 5 signingTime
			process_integer_feature("CRYPT_CERTINFO_CMS_SIGNINGTIME")

			-- 1 2 840 113549 1 9 6 counterSignature
			process_integer_feature("CRYPT_CERTINFO_CMS_COUNTERSIGNATURE")	-- counterSignature

			-- 1 2 840 113549 1 9 13 signingDescription
			process_integer_feature("CRYPT_CERTINFO_CMS_SIGNINGDESCRIPTION")

			-- 1 2 840 113549 1 9 15 sMIMECapabilities
			process_integer_feature("CRYPT_CERTINFO_CMS_SMIMECAPABILITIES")
			process_integer_feature("CRYPT_CERTINFO_CMS_SMIMECAP_3DES")				-- 3DES encryption
			process_integer_feature("CRYPT_CERTINFO_CMS_SMIMECAP_AES")				-- AES encryption
			process_integer_feature("CRYPT_CERTINFO_CMS_SMIMECAP_CAST128")			-- CAST-128 encryption
			process_integer_feature("CRYPT_CERTINFO_CMS_SMIMECAP_IDEA")				-- IDEA encryption
			process_integer_feature("CRYPT_CERTINFO_CMS_SMIMECAP_RC2")				-- RC2 encryption (w.128 key)
			process_integer_feature("CRYPT_CERTINFO_CMS_SMIMECAP_RC5")				-- RC5 encryption (w.128 key)
			process_integer_feature("CRYPT_CERTINFO_CMS_SMIMECAP_SKIPJACK")			-- Skipjack encryption
			process_integer_feature("CRYPT_CERTINFO_CMS_SMIMECAP_DES")				-- DES encryption
			process_integer_feature("CRYPT_CERTINFO_CMS_SMIMECAP_PREFERSIGNEDDATA")	-- preferSignedData
			process_integer_feature("CRYPT_CERTINFO_CMS_SMIMECAP_CANNOTDECRYPTANY")	-- canNotDecryptAny

			-- 1 2 840 113549 1 9 16 2 1 receiptRequest
			process_integer_feature("CRYPT_CERTINFO_CMS_RECEIPTREQUEST")
			process_integer_feature("CRYPT_CERTINFO_CMS_RECEIPT_CONTENTIDENTIFIER") -- contentIdentifier
			process_integer_feature("CRYPT_CERTINFO_CMS_RECEIPT_FROM")				-- receiptsFrom
			process_integer_feature("CRYPT_CERTINFO_CMS_RECEIPT_TO")				-- receiptsTo

			-- 1 2 840 113549 1 9 16 2 2 essSecurityLabel
			process_integer_feature("CRYPT_CERTINFO_CMS_SECURITYLABEL")
			process_integer_feature("CRYPT_CERTINFO_CMS_SECLABEL_CLASSIFICATION")	-- securityClassification
			process_integer_feature("CRYPT_CERTINFO_CMS_SECLABEL_POLICY")			-- securityPolicyIdentifier
			process_integer_feature("CRYPT_CERTINFO_CMS_SECLABEL_PRIVACYMARK")		-- privacyMark
			process_integer_feature("CRYPT_CERTINFO_CMS_SECLABEL_CATTYPE")			-- securityCategories.securityCategory.type
			process_integer_feature("CRYPT_CERTINFO_CMS_SECLABEL_CATVALUE")			-- securityCategories.securityCategory.value

			-- 1 2 840 113549 1 9 16 2 3 mlExpansionHistory
			process_integer_feature("CRYPT_CERTINFO_CMS_MLEXPANSIONHISTORY")
			process_integer_feature("CRYPT_CERTINFO_CMS_MLEXP_ENTITYIDENTIFIER") -- mlData.mailListIdentifier.issuerAndSerialNumber
			process_integer_feature("CRYPT_CERTINFO_CMS_MLEXP_TIME")			-- mlData.expansionTime
			process_integer_feature("CRYPT_CERTINFO_CMS_MLEXP_NONE")			-- mlData.mlReceiptPolicy.none
			process_integer_feature("CRYPT_CERTINFO_CMS_MLEXP_INSTEADOF")		-- mlData.mlReceiptPolicy.insteadOf.generalNames.generalName
			process_integer_feature("CRYPT_CERTINFO_CMS_MLEXP_INADDITIONTO")	-- mlData.mlReceiptPolicy.inAdditionTo.generalNames.generalName

			-- 1 2 840 113549 1 9 16 2 4 contentHints
			process_integer_feature("CRYPT_CERTINFO_CMS_CONTENTHINTS")
			process_integer_feature("CRYPT_CERTINFO_CMS_CONTENTHINT_DESCRIPTION")	-- contentDescription
			process_integer_feature("CRYPT_CERTINFO_CMS_CONTENTHINT_TYPE")			-- contentType

			-- 1 2 840 113549 1 9 16 2 9 equivalentLabels
			process_integer_feature("CRYPT_CERTINFO_CMS_EQUIVALENTLABEL")
			process_integer_feature("CRYPT_CERTINFO_CMS_EQVLABEL_POLICY")			-- securityPolicyIdentifier
			process_integer_feature("CRYPT_CERTINFO_CMS_EQVLABEL_CLASSIFICATION") 	-- securityClassification
			process_integer_feature("CRYPT_CERTINFO_CMS_EQVLABEL_PRIVACYMARK")		-- privacyMark
			process_integer_feature("CRYPT_CERTINFO_CMS_EQVLABEL_CATTYPE")			-- securityCategories.securityCategory.type
			process_integer_feature("CRYPT_CERTINFO_CMS_EQVLABEL_CATVALUE")			-- securityCategories.securityCategory.value

			-- 1 2 840 113549 1 9 16 2 12 signingCertificate
			process_integer_feature("CRYPT_CERTINFO_CMS_SIGNINGCERTIFICATE")
			process_integer_feature("CRYPT_CERTINFO_CMS_SIGNINGCERT_ESSCERTID") -- certs.essCertID
			process_integer_feature("CRYPT_CERTINFO_CMS_SIGNINGCERT_POLICIES")	-- policies.policyInformation.policyIdentifier

			-- 1 2 840 113549 1 9 16 2 15 signaturePolicyID
			process_integer_feature("CRYPT_CERTINFO_CMS_SIGNATUREPOLICYID")
			process_integer_feature("CRYPT_CERTINFO_CMS_SIGPOLICYID")			-- sigPolicyID
			process_integer_feature("CRYPT_CERTINFO_CMS_SIGPOLICYHASH")			-- sigPolicyHash
			process_integer_feature("CRYPT_CERTINFO_CMS_SIGPOLICY_CPSURI")		-- sigPolicyQualifiers.sigPolicyQualifier.cPSuri
			process_integer_feature("CRYPT_CERTINFO_CMS_SIGPOLICY_ORGANIZATION")
				-- sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef.organization
			process_integer_feature("CRYPT_CERTINFO_CMS_SIGPOLICY_NOTICENUMBERS")
				-- sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef.noticeNumbers
			process_integer_feature("CRYPT_CERTINFO_CMS_SIGPOLICY_EXPLICITTEXT")
				-- sigPolicyQualifiers.sigPolicyQualifier.userNotice.explicitText

			-- 1 2 840 113549 1 9 16 9 signatureTypeIdentifier
			process_integer_feature("CRYPT_CERTINFO_CMS_SIGTYPEIDENTIFIER")
			process_integer_feature("CRYPT_CERTINFO_CMS_SIGTYPEID_ORIGINATORSIG") -- originatorSig
			process_integer_feature("CRYPT_CERTINFO_CMS_SIGTYPEID_DOMAINSIG")	-- domainSig
			process_integer_feature("CRYPT_CERTINFO_CMS_SIGTYPEID_ADDITIONALATTRIBUTES") -- additionalAttributesSig
			process_integer_feature("CRYPT_CERTINFO_CMS_SIGTYPEID_REVIEWSIG")	-- reviewSig

			-- 1 2 840 113549 1 9 25 3 randomNonce
			process_integer_feature("CRYPT_CERTINFO_CMS_NONCE")				-- randomNonce

			-- SCEP attributes:
			-- 2 16 840 1 113733 1 9 2 messageType
			-- 2 16 840 1 113733 1 9 3 pkiStatus
			-- 2 16 840 1 113733 1 9 4 failInfo
			-- 2 16 840 1 113733 1 9 5 senderNonce
			-- 2 16 840 1 113733 1 9 6 recipientNonce
			-- 2 16 840 1 113733 1 9 7 transID
			process_integer_feature("CRYPT_CERTINFO_SCEP_MESSAGETYPE")		-- messageType
			process_integer_feature("CRYPT_CERTINFO_SCEP_PKISTATUS")		-- pkiStatus
			process_integer_feature("CRYPT_CERTINFO_SCEP_FAILINFO")			-- failInfo
			process_integer_feature("CRYPT_CERTINFO_SCEP_SENDERNONCE")		-- senderNonce
			process_integer_feature("CRYPT_CERTINFO_SCEP_RECIPIENTNONCE")	-- recipientNonce
			process_integer_feature("CRYPT_CERTINFO_SCEP_TRANSACTIONID")	-- transID

			-- 1 3 6 1 4 1 311 2 1 10 spcAgencyInfo
			process_integer_feature("CRYPT_CERTINFO_CMS_SPCAGENCYINFO")
			process_integer_feature("CRYPT_CERTINFO_CMS_SPCAGENCYURL")		-- spcAgencyInfo.url

			-- 1 3 6 1 4 1 311 2 1 11 spcStatementType
			process_integer_feature("CRYPT_CERTINFO_CMS_SPCSTATEMENTTYPE")
			process_integer_feature("CRYPT_CERTINFO_CMS_SPCSTMT_INDIVIDUALCODESIGNING")	-- individualCodeSigning
			process_integer_feature("CRYPT_CERTINFO_CMS_SPCSTMT_COMMERCIALCODESIGNING")	-- commercialCodeSigning

			-- 1 3 6 1 4 1 311 2 1 12 spcOpusInfo
			process_integer_feature("CRYPT_CERTINFO_CMS_SPCOPUSINFO")
			process_integer_feature("CRYPT_CERTINFO_CMS_SPCOPUSINFO_NAME")	-- spcOpusInfo.name
			process_integer_feature("CRYPT_CERTINFO_CMS_SPCOPUSINFO_URL")	-- spcOpusInfo.url


			--********************
			-- Keyset attributes
			--********************

			process_integer_feature("CRYPT_KEYINFO_QUERY")			-- Keyset query
			process_integer_feature("CRYPT_KEYINFO_QUERY_REQUESTS")	-- Query of requests in cert store


			--********************
			-- Device attributes
			--********************

			process_integer_feature("CRYPT_DEVINFO_INITIALISE")				-- Initialise device for use
			process_integer_feature("CRYPT_DEVINFO_INITIALIZE")
			process_integer_feature("CRYPT_DEVINFO_AUTHENT_USER")			-- Authenticate user to device
			process_integer_feature("CRYPT_DEVINFO_AUTHENT_SUPERVISOR")		-- Authenticate supervisor to dev.*/
			process_integer_feature("CRYPT_DEVINFO_SET_AUTHENT_USER")		-- Set user authent.value
			process_integer_feature("CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR")	-- Set supervisor auth.val.*/
			process_integer_feature("CRYPT_DEVINFO_ZEROISE")				-- Zeroise device
			process_integer_feature("CRYPT_DEVINFO_ZEROIZE")
			process_integer_feature("CRYPT_DEVINFO_LOGGEDIN")				-- Whether user is logged in
			process_integer_feature("CRYPT_DEVINFO_LABEL")					-- Device/token label

			--**********************
			-- Envelope attributes
			--**********************

			-- Pseudo-information on an envelope or meta-information which is used to
			-- control the way that data in an envelope is processed
			process_integer_feature("CRYPT_ENVINFO_DATASIZE")				-- Data size information
			process_integer_feature("CRYPT_ENVINFO_COMPRESSION")			-- Compression information
			process_integer_feature("CRYPT_ENVINFO_CONTENTTYPE")			-- Inner CMS content type
			process_integer_feature("CRYPT_ENVINFO_DETACHEDSIGNATURE")		-- Generate CMS detached signature
			process_integer_feature("CRYPT_ENVINFO_SIGNATURE_RESULT")		-- Signature check result
			process_integer_feature("CRYPT_ENVINFO_MAC")					-- Use MAC instead of encrypting

			-- Resources required for enveloping/deenveloping
			process_integer_feature("CRYPT_ENVINFO_PASSWORD")				-- User password
			process_integer_feature("CRYPT_ENVINFO_KEY")					-- Conventional encryption key
			process_integer_feature("CRYPT_ENVINFO_SIGNATURE")				-- Signature/signature check key
			process_integer_feature("CRYPT_ENVINFO_SIGNATURE_EXTRADATA")	-- Extra information added to CMS sigs
			process_integer_feature("CRYPT_ENVINFO_RECIPIENT")				-- Recipient email address
			process_integer_feature("CRYPT_ENVINFO_PUBLICKEY")				-- PKC encryption key
			process_integer_feature("CRYPT_ENVINFO_PRIVATEKEY")				-- PKC decryption key
			process_integer_feature("CRYPT_ENVINFO_PRIVATEKEY_LABEL")		-- Label of PKC decryption key
			process_integer_feature("CRYPT_ENVINFO_ORIGINATOR")				-- Originator info/key
			process_integer_feature("CRYPT_ENVINFO_SESSIONKEY")				-- Session key
			process_integer_feature("CRYPT_ENVINFO_HASH")					-- Hash value
			process_integer_feature("CRYPT_ENVINFO_TIMESTAMP")				-- Timestamp information

			-- Keysets used to retrieve keys needed for enveloping/deenveloping
			process_integer_feature("CRYPT_ENVINFO_KEYSET_SIGCHECK")		-- Signature check keyset
			process_integer_feature("CRYPT_ENVINFO_KEYSET_ENCRYPT")			-- PKC encryption keyset
			process_integer_feature("CRYPT_ENVINFO_KEYSET_DECRYPT")			-- PKC decryption keyset

			--*********************
			-- Session attributes
			--*********************

			-- Pseudo-information on a session or meta-information which is used to
			-- control the way that a session is managed

			-- Pseudo-information about the session
			process_integer_feature("CRYPT_SESSINFO_ACTIVE")				-- Whether session is active
			process_integer_feature("CRYPT_SESSINFO_CONNECTIONACTIVE")		-- Whether network connection is active

			-- Security-related information
			process_integer_feature("CRYPT_SESSINFO_USERNAME")				-- User name
			process_integer_feature("CRYPT_SESSINFO_PASSWORD")				-- Password
			process_integer_feature("CRYPT_SESSINFO_PRIVATEKEY")			-- Server/client private key
			process_integer_feature("CRYPT_SESSINFO_KEYSET")				-- Certificate store
			process_integer_feature("CRYPT_SESSINFO_AUTHRESPONSE")			-- Session authorisation OK
	
			-- Client/server information
			process_integer_feature("CRYPT_SESSINFO_SERVER_NAME")			-- Server name
			process_integer_feature("CRYPT_SESSINFO_SERVER_PORT")			-- Server port number
			process_integer_feature("CRYPT_SESSINFO_SERVER_FINGERPRINT")	-- Server key fingerprint
			process_integer_feature("CRYPT_SESSINFO_CLIENT_NAME")			-- Client name
			process_integer_feature("CRYPT_SESSINFO_CLIENT_PORT")			-- Client port number
			process_integer_feature("CRYPT_SESSINFO_SESSION")				-- Transport mechanism
			process_integer_feature("CRYPT_SESSINFO_NETWORKSOCKET")			-- User-supplied network socket

			-- Generic protocol-related information
			process_integer_feature("CRYPT_SESSINFO_VERSION")				-- Protocol version
			process_integer_feature("CRYPT_SESSINFO_REQUEST")				-- Cert.request object
			process_integer_feature("CRYPT_SESSINFO_RESPONSE")				-- Cert.response object
			process_integer_feature("CRYPT_SESSINFO_CACERTIFICATE")			-- Issuing CA certificate

			-- Protocol-specific information
			process_integer_feature("CRYPT_SESSINFO_TSP_MSGIMPRINT")		-- TSP message imprint
			process_integer_feature("CRYPT_SESSINFO_CMP_REQUESTTYPE")		-- Request type
			process_integer_feature("CRYPT_SESSINFO_CMP_PKIBOOT")			-- Enable PKIBoot facility
			process_integer_feature("CRYPT_SESSINFO_CMP_PRIVKEYSET")		-- Private-key keyset
			process_integer_feature("CRYPT_SESSINFO_SSH_CHANNEL")			-- SSH current channel
			process_integer_feature("CRYPT_SESSINFO_SSH_CHANNEL_TYPE")		-- SSH channel type
			process_integer_feature("CRYPT_SESSINFO_SSH_CHANNEL_ARG1")		-- SSH channel argument 1
			process_integer_feature("CRYPT_SESSINFO_SSH_CHANNEL_ARG2")		-- SSH channel argument 2
			process_integer_feature("CRYPT_SESSINFO_SSH_CHANNEL_ACTIVE")	-- SSH channel active


			--*********************
			-- User attributes
			--*********************

			-- Security-related information
			process_integer_feature("CRYPT_USERINFO_PASSWORD")		-- Password

			-- User role-related information
			process_integer_feature("CRYPT_USERINFO_CAKEY_CERTSIGN")	-- CA cert signing key
			process_integer_feature("CRYPT_USERINFO_CAKEY_CRLSIGN")		-- CA CRL signing key
			process_integer_feature("CRYPT_USERINFO_CAKEY_RTCSSIGN")	-- CA RTCS signing key
			process_integer_feature("CRYPT_USERINFO_CAKEY_OCSPSIGN")	-- CA OCSP signing key


--##################################################################################################
		end

feature -- Attribute Subtypes and Related Values

	process_attribute_subtypes is
		do
		
			-- Flags for the X.509 keyUsage extension

			process_hexadecimal_feature("CRYPT_KEYUSAGE_NONE")
			process_hexadecimal_feature("CRYPT_KEYUSAGE_DIGITALSIGNATURE")
			process_hexadecimal_feature("CRYPT_KEYUSAGE_NONREPUDIATION")
			process_hexadecimal_feature("CRYPT_KEYUSAGE_KEYENCIPHERMENT")
			process_hexadecimal_feature("CRYPT_KEYUSAGE_DATAENCIPHERMENT")
			process_hexadecimal_feature("CRYPT_KEYUSAGE_KEYAGREEMENT")
			process_hexadecimal_feature("CRYPT_KEYUSAGE_KEYCERTSIGN")
			process_hexadecimal_feature("CRYPT_KEYUSAGE_CRLSIGN")
			process_hexadecimal_feature("CRYPT_KEYUSAGE_ENCIPHERONLY")
			process_hexadecimal_feature("CRYPT_KEYUSAGE_DECIPHERONLY")
			process_hexadecimal_feature("CRYPT_KEYUSAGE_LAST")

			-- X.509 cRLReason and cryptlib cRLExtReason codes

			process_integer_feature("CRYPT_CRLREASON_UNSPECIFIED")
			process_integer_feature("CRYPT_CRLREASON_KEYCOMPROMISE")
			process_integer_feature("CRYPT_CRLREASON_CACOMPROMISE")
			process_integer_feature("CRYPT_CRLREASON_AFFILIATIONCHANGED")
			process_integer_feature("CRYPT_CRLREASON_SUPERSEDED")
			process_integer_feature("CRYPT_CRLREASON_CESSATIONOFOPERATION")
			process_integer_feature("CRYPT_CRLREASON_CERTIFICATEHOLD")
			process_integer_feature("CRYPT_CRLREASON_REMOVEFROMCRL")
			process_integer_feature("CRYPT_CRLREASON_PRIVILEGEWITHDRAWN")
			process_integer_feature("CRYPT_CRLREASON_AACOMPROMISE")
			process_integer_feature("CRYPT_CRLREASON_LAST")
			process_integer_feature("CRYPT_CRLREASON_NEVERVALID")
			process_integer_feature("CRYPT_CRLEXTREASON_LAST")

			--	X.509 CRL reason flags.  These identify the same thing as the cRLReason
			--	codes but allow for multiple reasons to be specified.  Note that these
			--	don't follow the X.509 naming since in that scheme the enumerated types
			--	and bitflags have the same names

			process_hexadecimal_feature("CRYPT_CRLREASONFLAG_UNUSED")
			process_hexadecimal_feature("CRYPT_CRLREASONFLAG_KEYCOMPROMISE")
			process_hexadecimal_feature("CRYPT_CRLREASONFLAG_CACOMPROMISE")
			process_hexadecimal_feature("CRYPT_CRLREASONFLAG_AFFILIATIONCHANGED")
			process_hexadecimal_feature("CRYPT_CRLREASONFLAG_SUPERSEDED")
			process_hexadecimal_feature("CRYPT_CRLREASONFLAG_CESSATIONOFOPERATION")
			process_hexadecimal_feature("CRYPT_CRLREASONFLAG_CERTIFICATEHOLD")
			process_hexadecimal_feature("CRYPT_CRLREASONFLAG_LAST")

			-- X.509 CRL holdInstruction codes

			process_integer_feature("CRYPT_HOLDINSTRUCTION_NONE")
			process_integer_feature("CRYPT_HOLDINSTRUCTION_CALLISSUER")
			process_integer_feature("CRYPT_HOLDINSTRUCTION_REJECT")
			process_integer_feature("CRYPT_HOLDINSTRUCTION_PICKUPTOKEN")
			process_integer_feature("CRYPT_HOLDINSTRUCTION_LAST")

			-- Certificate checking compliance levels

			process_integer_feature("CRYPT_COMPLIANCELEVEL_OBLIVIOUS")
			process_integer_feature("CRYPT_COMPLIANCELEVEL_REDUCED")
			process_integer_feature("CRYPT_COMPLIANCELEVEL_STANDARD")
			process_integer_feature("CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL")
			process_integer_feature("CRYPT_COMPLIANCELEVEL_PKIX_FULL")
			process_integer_feature("CRYPT_COMPLIANCELEVEL_LAST")

			-- Flags for the Netscape netscape-cert-type extension

			process_hexadecimal_feature("CRYPT_NS_CERTTYPE_SSLCLIENT")
			process_hexadecimal_feature("CRYPT_NS_CERTTYPE_SSLSERVER")
			process_hexadecimal_feature("CRYPT_NS_CERTTYPE_SMIME")
			process_hexadecimal_feature("CRYPT_NS_CERTTYPE_OBJECTSIGNING")
			process_hexadecimal_feature("CRYPT_NS_CERTTYPE_RESERVED")
			process_hexadecimal_feature("CRYPT_NS_CERTTYPE_SSLCA")
			process_hexadecimal_feature("CRYPT_NS_CERTTYPE_SMIMECA")
			process_hexadecimal_feature("CRYPT_NS_CERTTYPE_OBJECTSIGNINGCA")
			process_hexadecimal_feature("CRYPT_NS_CERTTYPE_LAST")

			-- Flags for the SET certificate-type extension

			process_hexadecimal_feature("CRYPT_SET_CERTTYPE_CARD")
			process_hexadecimal_feature("CRYPT_SET_CERTTYPE_MER")
			process_hexadecimal_feature("CRYPT_SET_CERTTYPE_PGWY")
			process_hexadecimal_feature("CRYPT_SET_CERTTYPE_CCA")
			process_hexadecimal_feature("CRYPT_SET_CERTTYPE_MCA")
			process_hexadecimal_feature("CRYPT_SET_CERTTYPE_PCA")
			process_hexadecimal_feature("CRYPT_SET_CERTTYPE_GCA")
			process_hexadecimal_feature("CRYPT_SET_CERTTYPE_BCA")
			process_hexadecimal_feature("CRYPT_SET_CERTTYPE_RCA")
			process_hexadecimal_feature("CRYPT_SET_CERTTYPE_ACQ")
			process_hexadecimal_feature("CRYPT_SET_CERTTYPE_LAST")

			-- CMS contentType values

			process_integer_feature("CRYPT_CONTENT_NONE")
			process_integer_feature("CRYPT_CONTENT_DATA")
			process_integer_feature("CRYPT_CONTENT_SIGNEDDATA")
			process_integer_feature("CRYPT_CONTENT_ENVELOPEDDATA")
			process_integer_feature("CRYPT_CONTENT_SIGNEDANDENVELOPEDDATA")
			process_integer_feature("CRYPT_CONTENT_DIGESTEDDATA")
			process_integer_feature("CRYPT_CONTENT_ENCRYPTEDDATA")
			process_integer_feature("CRYPT_CONTENT_COMPRESSEDDATA")
			process_integer_feature("CRYPT_CONTENT_TSTINFO")
			process_integer_feature("CRYPT_CONTENT_SPCINDIRECTDATACONTEXT")
			process_integer_feature("CRYPT_CONTENT_RTCSREQUEST")
			process_integer_feature("CRYPT_CONTENT_RTCSRESPONSE")
			process_integer_feature("CRYPT_CONTENT_RTCSRESPONSE_EXT")
			process_integer_feature("CRYPT_CONTENT_LAST")

			-- ESS securityClassification codes

			process_integer_feature("CRYPT_CLASSIFICATION_UNMARKED")
			process_integer_feature("CRYPT_CLASSIFICATION_UNCLASSIFIED")
			process_integer_feature("CRYPT_CLASSIFICATION_RESTRICTED")
			process_integer_feature("CRYPT_CLASSIFICATION_CONFIDENTIAL")
			process_integer_feature("CRYPT_CLASSIFICATION_SECRET")
			process_integer_feature("CRYPT_CLASSIFICATION_TOP_SECRET")
			process_integer_feature("CRYPT_CLASSIFICATION_LAST")

			-- RTCS certificate status

			process_integer_feature("CRYPT_CERTSTATUS_VALID")
			process_integer_feature("CRYPT_CERTSTATUS_NOTVALID")
			process_integer_feature("CRYPT_CERTSTATUS_NONAUTHORITATIVE")
			process_integer_feature("CRYPT_CERTSTATUS_UNKNOWN")

			-- OCSP revocation status

			process_integer_feature("CRYPT_OCSPSTATUS_NOTREVOKED")
			process_integer_feature("CRYPT_OCSPSTATUS_REVOKED")
			process_integer_feature("CRYPT_OCSPSTATUS_UNKNOWN")


			-- The amount of detail to include in signatures
			-- when signing certificate objects

			process_integer_feature("CRYPT_SIGNATURELEVEL_NONE")			-- Include only signature
			process_integer_feature("CRYPT_SIGNATURELEVEL_SIGNERCERT")		-- Include signer cert
			process_integer_feature("CRYPT_SIGNATURELEVEL_ALL")				-- Include all relevant info
			process_integer_feature("CRYPT_SIGNATURELEVEL_LAST")			-- Last possible sig.level type

			-- The certificate export format type, which defines the format
			-- in which a certificate object is exported

			process_integer_feature("CRYPT_CERTFORMAT_NONE")				-- No certificate format
			process_integer_feature("CRYPT_CERTFORMAT_CERTIFICATE")			-- DER-encoded certificate
			process_integer_feature("CRYPT_CERTFORMAT_CERTCHAIN")			-- PKCS #7 certificate chain
			process_integer_feature("CRYPT_CERTFORMAT_TEXT_CERTIFICATE")	-- base-64 wrapped cert
			process_integer_feature("CRYPT_CERTFORMAT_TEXT_CERTCHAIN")		-- base-64 wrapped cert chain
			process_integer_feature("CRYPT_CERTFORMAT_XML_CERTIFICATE")		-- XML wrapped cert
			process_integer_feature("CRYPT_CERTFORMAT_XML_CERTCHAIN")		-- XML wrapped cert chain
			process_integer_feature("CRYPT_CERTFORMAT_LAST")				-- Last possible cert.format type

			-- CMP request types

			process_integer_feature("CRYPT_REQUESTTYPE_NONE")				-- No request type
			process_integer_feature("CRYPT_REQUESTTYPE_INITIALISATION")		-- Initialisation request
			process_integer_feature("CRYPT_REQUESTTYPE_INITIALIZATION")
			process_integer_feature("CRYPT_REQUESTTYPE_CERTIFICATE")		-- Certification request
			process_integer_feature("CRYPT_REQUESTTYPE_KEYUPDATE")			-- Key update request
			process_integer_feature("CRYPT_REQUESTTYPE_REVOCATION")			-- Cert revocation request
			process_integer_feature("CRYPT_REQUESTTYPE_PKIBOOT")			-- PKIBoot request
			process_integer_feature("CRYPT_REQUESTTYPE_LAST")				-- Last possible request type

			-- Key ID types

			process_integer_feature("CRYPT_KEYID_NONE")					-- No key ID type
			process_integer_feature("CRYPT_KEYID_NAME")					-- Key owner name
			process_integer_feature("CRYPT_KEYID_URI")					-- Key owner URI
			process_integer_feature("CRYPT_KEYID_EMAIL") 				-- Synonym: owner email addr.
			process_integer_feature("CRYPT_KEYID_LAST")					-- Last possible key ID type

			-- The encryption object types

			process_integer_feature("CRYPT_OBJECT_NONE")				-- No object type
			process_integer_feature("CRYPT_OBJECT_ENCRYPTED_KEY")		-- Conventionally encrypted key
			process_integer_feature("CRYPT_OBJECT_PKCENCRYPTED_KEY")	-- PKC-encrypted key
			process_integer_feature("CRYPT_OBJECT_KEYAGREEMENT")		-- Key agreement information
			process_integer_feature("CRYPT_OBJECT_SIGNATURE")			-- Signature
			process_integer_feature("CRYPT_OBJECT_LAST")				-- Last possible object type

			-- Object/attribute error type information

			process_integer_feature("CRYPT_ERRTYPE_NONE")				-- No error information
			process_integer_feature("CRYPT_ERRTYPE_ATTR_SIZE")			-- Attribute data too small or large
			process_integer_feature("CRYPT_ERRTYPE_ATTR_VALUE")			-- Attribute value is invalid
			process_integer_feature("CRYPT_ERRTYPE_ATTR_ABSENT")		-- Required attribute missing
			process_integer_feature("CRYPT_ERRTYPE_ATTR_PRESENT")		-- Non-allowed attribute present
			process_integer_feature("CRYPT_ERRTYPE_CONSTRAINT")			-- Cert: Constraint violation in object
			process_integer_feature("CRYPT_ERRTYPE_ISSUERCONSTRAINT")	-- Cert: Constraint viol.in issuing cert
			process_integer_feature("CRYPT_ERRTYPE_LAST")				-- Last possible error info type

			-- Cert store management action type

			process_integer_feature("CRYPT_CERTACTION_NONE")					-- No cert management action
			process_integer_feature("CRYPT_CERTACTION_CREATE")					-- Create cert store
			process_integer_feature("CRYPT_CERTACTION_CONNECT")					-- Connect to cert store
			process_integer_feature("CRYPT_CERTACTION_DISCONNECT")				-- Disconnect from cert store
			process_integer_feature("CRYPT_CERTACTION_ERROR")					-- Error information
			process_integer_feature("CRYPT_CERTACTION_ADDUSER")					-- Add PKI user
			process_integer_feature("CRYPT_CERTACTION_DELETEUSER")				-- Delete PKI user
			process_integer_feature("CRYPT_CERTACTION_REQUEST_CERT")			-- Cert request
			process_integer_feature("CRYPT_CERTACTION_REQUEST_RENEWAL")			-- Cert renewal request
			process_integer_feature("CRYPT_CERTACTION_REQUEST_REVOCATION")		-- Cert revocation request
			process_integer_feature("CRYPT_CERTACTION_CERT_CREATION")			-- Cert creation
			process_integer_feature("CRYPT_CERTACTION_CERT_CREATION_COMPLETE")	-- Confirmation of cert creation
			process_integer_feature("CRYPT_CERTACTION_CERT_CREATION_DROP")		-- Cancellation of cert creation
			process_integer_feature("CRYPT_CERTACTION_CERT_CREATION_REVERSE")	-- Cancel of creation w.revocation
			process_integer_feature("CRYPT_CERTACTION_RESTART_CLEANUP") 		-- Delete reqs after restart
			process_integer_feature("CRYPT_CERTACTION_RESTART_REVOKE_CERT") 	-- Complete revocation after restart
			process_integer_feature("CRYPT_CERTACTION_ISSUE_CERT")				-- Cert issue
			process_integer_feature("CRYPT_CERTACTION_ISSUE_CRL")				-- CRL issue
			process_integer_feature("CRYPT_CERTACTION_REVOKE_CERT")				-- Cert revocation
			process_integer_feature("CRYPT_CERTACTION_EXPIRE_CERT")				-- Cert expiry
			process_integer_feature("CRYPT_CERTACTION_CLEANUP")					-- Clean up on restart
			process_integer_feature("CRYPT_CERTACTION_LAST")					-- Last possible cert store log action



			--/****************************************************************************
			--*																			*
			--*								General Constants							*
			--*																			*
			--****************************************************************************/

			-- The maximum user key size - 2048 bits

			process_integer_feature("CRYPT_MAX_KEYSIZE")

			-- The maximum IV size - 256 bits

			process_integer_feature("CRYPT_MAX_IVSIZE")

			-- The maximum public-key component size - 4096 bits

			process_integer_feature("CRYPT_MAX_PKCSIZE")

			-- The maximum hash size - 256 bits

			process_integer_feature("CRYPT_MAX_HASHSIZE")

			-- The maximum size of a text string (e.g.key owner name)

			process_integer_feature("CRYPT_MAX_TEXTSIZE")

			-- A magic value indicating that the default setting for this parameter
			--   should be used

			process_integer_feature("CRYPT_USE_DEFAULT")

			-- A magic value for unused parameters

			process_integer_feature("CRYPT_UNUSED")

			-- Whether the PKC key is a public or private key

			process_integer_feature("CRYPT_KEYTYPE_PRIVATE")
			process_integer_feature("CRYPT_KEYTYPE_PUBLIC")

			-- The type of information polling to perform to get random seed information

			process_integer_feature("CRYPT_RANDOM_FASTPOLL")
			process_integer_feature("CRYPT_RANDOM_SLOWPOLL")

			-- Cursor positioning codes for certificate/CRL extensions

			process_integer_feature("CRYPT_CURSOR_FIRST")
			process_integer_feature("CRYPT_CURSOR_PREVIOUS")
			process_integer_feature("CRYPT_CURSOR_NEXT")
			process_integer_feature("CRYPT_CURSOR_LAST")

			-- Keyset open options

			process_integer_feature("CRYPT_KEYOPT_NONE")			-- No options
			process_integer_feature("CRYPT_KEYOPT_READONLY")		-- Open keyset in read-only mode
			process_integer_feature("CRYPT_KEYOPT_CREATE")			-- Create a new keyset
			process_integer_feature("CRYPT_KEYOPT_LAST")			-- Last possible key option type


--###############################################################################################

		end

feature -- Status Codes

	process_error_features is
		do

			-- No error in function call

			process_integer_feature("CRYPT_OK")		-- No error

			-- Error in parameters passed to function

			process_integer_feature("CRYPT_ERROR_PARAM1")	-- Bad argument, parameter 1
			process_integer_feature("CRYPT_ERROR_PARAM2")	-- Bad argument, parameter 2
			process_integer_feature("CRYPT_ERROR_PARAM3")	-- Bad argument, parameter 3
			process_integer_feature("CRYPT_ERROR_PARAM4")	-- Bad argument, parameter 4
			process_integer_feature("CRYPT_ERROR_PARAM5")	-- Bad argument, parameter 5
			process_integer_feature("CRYPT_ERROR_PARAM6")	-- Bad argument, parameter 6
			process_integer_feature("CRYPT_ERROR_PARAM7")	-- Bad argument, parameter 7

			-- Errors due to insufficient resources

			process_integer_feature("CRYPT_ERROR_MEMORY")		-- Out of memory
			process_integer_feature("CRYPT_ERROR_NOTINITED")	-- Data has not been initialised
			process_integer_feature("CRYPT_ERROR_INITED")		-- Data has already been init'd
			process_integer_feature("CRYPT_ERROR_NOSECURE")		-- Opn.not avail.at requested sec.level
			process_integer_feature("CRYPT_ERROR_RANDOM")		-- No reliable random data available
			process_integer_feature("CRYPT_ERROR_FAILED")		-- Operation failed

			-- Security violations

			process_integer_feature("CRYPT_ERROR_NOTAVAIL")		-- This type of opn.not available
			process_integer_feature("CRYPT_ERROR_PERMISSION")	-- No permiss.to perform this operation
			process_integer_feature("CRYPT_ERROR_WRONGKEY")		-- Incorrect key used to decrypt data
			process_integer_feature("CRYPT_ERROR_INCOMPLETE")	-- Operation incomplete/still in progress
			process_integer_feature("CRYPT_ERROR_COMPLETE")		-- Operation complete/can't continue
			process_integer_feature("CRYPT_ERROR_TIMEOUT")		-- Operation timed out before completion
			process_integer_feature("CRYPT_ERROR_INVALID")		-- Invalid/inconsistent information
			process_integer_feature("CRYPT_ERROR_SIGNALLED")	-- Resource destroyed by extnl.event

			-- High-level function errors

			process_integer_feature("CRYPT_ERROR_OVERFLOW")		-- Resources/space exhausted
			process_integer_feature("CRYPT_ERROR_UNDERFLOW")	-- Not enough data available
			process_integer_feature("CRYPT_ERROR_BADDATA")		-- Bad/unrecognised data format
			process_integer_feature("CRYPT_ERROR_SIGNATURE")	-- Signature/integrity check failed

			-- Data access function errors

			process_integer_feature("CRYPT_ERROR_OPEN")			-- Cannot open object
			process_integer_feature("CRYPT_ERROR_READ")			-- Cannot read item from object
			process_integer_feature("CRYPT_ERROR_WRITE")		-- Cannot write item to object
			process_integer_feature("CRYPT_ERROR_NOTFOUND")		-- Requested item not found in object
			process_integer_feature("CRYPT_ERROR_DUPLICATE")	-- Item already present in object

			-- Data enveloping errors

			process_integer_feature("CRYPT_ENVELOPE_RESOURCE")	-- Need resource to proceed
		end
		
feature -- Generic code, to be factored out ....

	class_name: STRING
	file_name: STRING

	out_file: TEXT_FILE_WRITE
	
	set_class_name(a_name: STRING) is
			-- Initialize, based on class name
		do
			class_name := a_name
			file_name := "make_" + class_name.as_lower + ".c"
			create out_file.connect_to(file_name)
		--	if not out_file.is_connected then
		--		die
		--	end
		end

	include(s: STRING) is
			-- append an #include directive
		do
			out_file.put_string("#include %"")
			out_file.put_string(s)
			out_file.put_string("%"%N%N")
		end

	append_head is
			-- boiler-plate code for data declarations
			-- and start of 'main' routine
		do
			out_file.put_string("[
				char *class_head =
					"class %s\n"
					"\n"
					"feature\n"
					"\n";

				char *class_tail =
					"end\n";


			]")
			out_file.put_string("char *class_name = %"")
			out_file.put_string(class_name)
			out_file.put_string("%";%N%N")
			out_file.put_string("[
				int main(int ac, char **av) {

					printf(class_head, class_name);

			]")
		end

	process_integer_feature(s: STRING) is
		do
			out_file.put_string("%Tprintf(%"\t")
			out_file.put_string(s)
			out_file.put_string(": INTEGER is %%d\n%", ")
			out_file.put_string(s)
			out_file.put_string(");%N")
		end

	process_hexadecimal_feature(s: STRING) is
		do
			out_file.put_string("%Tprintf(%"\t")
			out_file.put_string(s)
			out_file.put_string(": INTEGER is 0x%%.8x\n%", ")
			out_file.put_string(s)
			out_file.put_string(");%N")
		end

	append_tail is
			-- Append tail and close output file
		do
			out_file.put_string("%Tprintf(class_tail);%N")
			out_file.put_string("}%N")
			out_file.disconnect
		end

end