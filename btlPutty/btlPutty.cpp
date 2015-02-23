
#include "stdafx.h"
#include "activeds.h"
#include "atlbase.h"

int main(int argc, char* argv[])
{
	HRESULT hr;
	IADs *pUser = NULL;

	void HUGEP *pArray = NULL;
	ULONG dwSLBound;
	ULONG dwSUBound;


	// Initialize COM before calling any ADSI functions or interfaces.
	CoInitialize(NULL);

	hr = ADsGetObject(L"LDAP://CN=Majid Ghader,OU=BTL USERS,OU=BTL,DC=btl-test,DC=com",
		IID_IADs,
		(void**)&pUser);
	if (SUCCEEDED(hr))
	{
		VARIANT varOS;

		VariantInit(&varOS);

		hr = pUser->Get(CComBSTR("puttySSHPrivateKey"), &varOS);

		if (SUCCEEDED(hr))
		{
			hr = SafeArrayGetLBound(V_ARRAY(&varOS),
				1,
				(long FAR *) &dwSLBound);

			hr = SafeArrayGetUBound(V_ARRAY(&varOS),
				1,
				(long FAR *) &dwSUBound);

			if (SUCCEEDED(hr))
			{
				hr = SafeArrayAccessData(V_ARRAY(&varOS), &pArray);
			}

			FILE *keyfile;
			fopen_s(&keyfile, "id_rsa.ppk", "w");
			fwrite(pArray, 1, dwSUBound - dwSLBound + 1, keyfile);
			fclose(keyfile);

			SafeArrayUnaccessData(V_ARRAY(&varOS));
			VariantClear(&varOS);
		}


		pUser->Release();
	}

	CoUninitialize();

	system("start pageant.exe id_rsa.ppk");
	system("start /B putty.exe majid@10.10.11.111");
	system("taskkill -IM pageant.exe");
}

