BITS	16
ORG	0x8000

alloc	equ	0x12A
update	equ	0x157
free	equ	0x1C3
print	equ	0x1F3
read	equ	0x205

;	mov	ax, hello
;	mov	bx, 15
;	call	print

main:
	in	al, 0x17
	cmp	al, 'R'
	je	readmem
	cmp	al, 'W'
	je	writemem
	cmp	al, 'S'
	je	dosys

	mov	ax, oops
	mov	bx, 8
	call	print

	jmp	main

readmem:
	call read_u16
	mov	bx, ax
	mov	ax, 0x4000
	call	print
	jmp	main

writemem:
	call read_u16
	mov	bx, ax
	mov	ax, 0x4000
	call	read
	jmp	main

dosys:
	call	read_u16
	push	ax
	call	read_u16
	push	ax
	call	read_u16
	push	ax
	call	read_u16
	push	100h ; do I need this?
	popf
	mov	dx, ax
	pop	cx
	pop	bx
	pop	ax
	vmcall
	jmp	main

read_u16:
	in	al, 0x17
	mov	bl, al
	in	al, 0x17
	mov	ah, al
	mov	al, bl
	ret

oops:
db	'Invalid', 0xA