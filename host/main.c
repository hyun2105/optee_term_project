/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

void Encryption(char* argv,TEEC_Operation* op,uint32_t* err_origin,TEEC_Session* sess);
//void Decryption();
int main(int argc,char** argv)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);


	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);
	if(argv[1][1] == 'e') {		//argv[1][1] ->e check   
	Encryption(argv[2],&op,&err_origin,&sess);
	}else if(argv[1][1] == 'd'){	
	Decryption(argv[2],argv[3],&op,&err_origin,&sess);
	}
	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
} 
void Encryption(char* argv,TEEC_Operation* op,uint32_t* err_origin,TEEC_Session* sess){
	printf("========================Encryption========================\n");			
	TEEC_Result res;	
	FILE* fp = fopen(argv,"r");
	char plaintext[1024] = {0,};
	char ciphertext[1024] = {0,};
	int len=1024;
	fread(plaintext, 1, 1024, fp);
	fclose(fp);
	op->params[0].tmpref.buffer= plaintext; //parameter suljeong
	op->params[0].tmpref.size = len;            
	res = TEEC_InvokeCommand(sess, TA_TEEencrypt_CMD_ENC_VALUE,op,
				 err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, *err_origin);
	memcpy(ciphertext,op->params[0].tmpref.buffer,len);
	fp = fopen("ciphertext.txt","w");
	fprintf(fp,"%s",ciphertext);
  	fclose(fp);
	fp = fopen("encryptedkey.txt","w");
	fprintf(fp,"%d",op->params[1].value.a);
  	fclose(fp);
}

void Decryption(char* textfilename,char* keyfilename,TEEC_Operation* op,uint32_t* err_origin,TEEC_Session* sess){
	printf("========================Decryption========================\n");
	TEEC_Result res;	
	FILE* fp = fopen(textfilename,"r");
	char plaintext[1024] = {0,};
	char ciphertext[1024] = {0,};
	char keytext[10] = {0,};
	int len=1024;
	fread(ciphertext, 1, 1024, fp);
	fclose(fp);
	op->params[0].tmpref.buffer= ciphertext;
	op->params[0].tmpref.size = len;
	FILE* fp2 = fopen(keyfilename,"r");
	fread(keytext, 1, 10,fp2);
	fclose(fp2);
	op->params[1].value.a= atoi(keytext);
	res = TEEC_InvokeCommand(sess, TA_TEEencrypt_CMD_DEC_VALUE,op,
				 err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, *err_origin);
	memcpy(plaintext,op->params[0].tmpref.buffer,len);
	fp = fopen("plaintext.txt","w");
	fprintf(fp,"%s",plaintext);
  	fclose(fp);
	fp = fopen("decryptedkey.txt","w");
	fprintf(fp,"%d",op->params[1].value.a);
  	fclose(fp);
}
	
	
