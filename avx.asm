IFDEF X64 ; --------------------------- x86-64

PUBLIC	isAvxSupported

ELSE ; --------------------------- x86

	.686P
	.XMM

PUBLIC	_isAvxSupported

ENDIF

_TEXT	SEGMENT

IFDEF X64 ; --------------------------- x86-64

isAvxSupported:

ELSE

_isAvxSupported:

ENDIF

    xor eax, eax
    cpuid
    cmp eax, 1 ; ������������ �� CPUID �������� eax = 1?
    jb not_supported
    mov eax, 1
    cpuid
    and ecx, 018000000h ; ���������, ��� ����������� ���� 27 (�� ���������� XSAVE/XRSTOR)
    cmp ecx, 018000000h ; � 28 (��������� AVX �����������)
    jne not_supported
    xor ecx, ecx ; ����� �������� XFEATURE_ENABLED_MASK/XCR0 ���� 0
    xgetbv ; ������� XFEATURE_ENABLED_MASK ������ � edx:eax
    and eax, 110b
    cmp eax, 110b ; ����������, ��� �� ��������� AVX �������� ��� ������������ ���������
    jne not_supported
    mov eax, 1
    ret
not_supported:
    xor eax, eax
    ret

_TEXT	ENDS

	END

