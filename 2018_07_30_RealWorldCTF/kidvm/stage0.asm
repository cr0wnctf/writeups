BITS	16
ORG	0x10

	mov	di, 0x8000
	mov	cx, di
load:
	in	al, 0x17
	stosb
	loop	load

	jmp	0x8000