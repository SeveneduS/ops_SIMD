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
    cmp eax, 1 ; Поддерживает ли CPUID параметр eax = 1?
    jb not_supported
    mov eax, 1
    cpuid
    and ecx, 018000000h ; Проверяем, что установлены биты 27 (ОС использует XSAVE/XRSTOR)
    cmp ecx, 018000000h ; и 28 (поддержка AVX процессором)
    jne not_supported
    xor ecx, ecx ; Номер регистра XFEATURE_ENABLED_MASK/XCR0 есть 0
    xgetbv ; Регистр XFEATURE_ENABLED_MASK теперь в edx:eax
    and eax, 110b
    cmp eax, 110b ; Убеждаемся, что ОС сохраняет AVX регистры при переключении контекста
    jne not_supported
    mov eax, 1
    ret
not_supported:
    xor eax, eax
    ret

_TEXT	ENDS

	END

