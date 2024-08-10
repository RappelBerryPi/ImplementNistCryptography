# The Birthday Problem

This is a well known problem when discussing cryptography and hash collisions.
The birthday Problem can be compared to the Monty Hall Problem.


A setup and description are below.

## problem

If I have an empty room, What is the minimum number of (chosen) people do I need to place
in the room to get a 100% guarantee that the next person that enters the room shares a
birthday with someone else in that room? The answer (of course) is 366 people. (A lot
of people here would argue that it only needs to be 365 people, but they of course
forget about leap years). If I have 366 people to choose from, I would guarantee that every
person in the room had a unique birthday, so that any new person (the 367th) is guaranteed
to share a birthday with someone else.

## Changing percentages

What if the people were randomly selected, obviously I would have to work off of probability
at this point. If I only get a new random person, I may not reach 100% quickly (remember I need
a person on every birthday and I cannot choose the birthday in this scenario), but what if I wanted
to know, at what point, is the next person entering the room likely to share a birthday with someone
else in the room with a (let's say) 50% chance? what If it was a 75% chance, or a 90% chance?

Most people would simply take that percentage of people and call it good, so If I wanted to get half a chance
that someone newly introduced into the room would share a birthday with someone I would need 183 (366 / 2) people.

What we need to do instead is shift our mindset to think about the probability that someone has a unique birthday
when they enter the room (because that's really the question we're asking). and this is compounding on the person
that came into the room before us.

### changing the model to think in probability

Note: For this section only I'm going to change the days of the year back to 365, because That's the way we typically
think about the year and it makes more logical sense.

+ When the first person enters the room, they have a 365/365 (1.0) probability that they don't share a birthday with anyone.
+ when the second person walks in the room, they have a (365/365 * 364/365) 99.726% probability that they don't share a birthday with anyone in the room.
+ when the third person walks in the room, they have a (365/365 * 364/365 * 363/365) 99.179% probability that they don't share a birthday with anyone in the room.

we can flip this to be in the positives. Let's reframe this to where they "do" share a birthday with someone in the room at a certain probability

+ the first person has a 0.000% probability of sharing a birthday with someone in the room.
+ the second person has a 0.274% probability of sharing a birthday with someone in the room.
+ 3 -> 0.820%
+ ...
+ ...

### The Question

The question as proposed above is this: when does that percentage of introducing someone new into the room increase
above our threshold percentage?

### The answer

In our example above, it turns out that the answer is 23.

I've created a (simple ) program in C called `birthday.c` that we can use to determine the number of people that we
would require in order to cross a certain threshold. Let's run it a few times and see how many people it takes to cross
that threshold and some additional. let's test for `25, 50, 75, 90, 95, and 99 percent` and we can then use that data to
generate some statistics.

```powershell
$ .\Birthday.exe 25
The 15 person (and every person after) gives at least a 25% chance that they will share a birthday with someone else
This is 4.109589% of the total number of possible birthdays
```

```powershell
$ .\Birthday.exe 50
The 23 person (and every person after) gives at least a 50% chance that they will share a birthday with someone else
This is 6.301370% of the total number of possible birthdays
```

```powershell
$ .\Birthday.exe 75
The 32 person (and every person after) gives at least a 75% chance that they will share a birthday with someone else
This is 8.767123% of the total number of possible birthdays
```

```powershell
$ .\Birthday.exe 90
The 41 person (and every person after) gives at least a 90% chance that they will share a birthday with someone else
This is 11.232877% of the total number of possible birthdays
```

```powershell
$ .\Birthday.exe 95
The 47 person (and every person after) gives at least a 95% chance that they will share a birthday with someone else
This is 12.876712% of the total number of possible birthdays
```

```powershell
$ .\Birthday.exe 99
The 57 person (and every person after) gives at least a 99% chance that they will share a birthday with someone else
This is 15.616438% of the total number of possible birthdays
```

## Application to Cryptography. 

There are three important security aspects of a hashing algorithm. These are the collision resistance, the second
pre-image resistance, and the pre-image resistance. And the security of the underlying anything about a system that
relies on a hashing algorithm rests in which of these traits you need to satisfy. These are described best by NIST, but
are described simply below.

+ pre-image resistance
  + the incapability to discover the pre-image (x) that produced the hash value (f(x)).
+ second pre-image resistance
  + knowing that x (pre-image) produced a hash value (f(x)), how difficult is it to find a second pre-image (y) that
    produces the same hash value (f(x) == f(y)).
+ collision resistance
  + find any two such pre-images (x, y) from the total set of possible pre-images that produce the same output (f(x) ==
    f(y)).

NOTE: collision resistance and second pre-image resistance sound the same and are built off of the same idea, but second
pre-image resistance means that you have to find a second value (y) that produces the same desired output as a known
input (x). collision resistance just cares about finding a collision, not necessarily a collision one you may want.

The birthday problem is how we decide the security-strength of collision resistance of an algorithm. 
For example, SHA-2 (256-bit) has a pre-image resistance of 256 bits (2^256), but a collision resistance of half of 
that - 128-bits (2^128). Why is that? where is the analysis? is it published? The answer to all of these will come
later, but for now, let's have some fun and do some math to understand ourselves.

### second program

I've created a second program (called hash.\[language\]) where the `language` is that ending for that file type. I plan
on doing this in many different languages, but sticking to major ones at first (C, C++, Java, python, COBOL (for all the
mainframers and IBM I ers out there), etc.).

The general steps are below, (leaving out more technical details like flipping percentage)

+ get the percentage threshold from the user, defaulting to 50% if none given.
+ get the domain in question (only focusing on 2 to the power inputted by the user as the second parameter) defaulting to 2**32
+ run the birthday problem on the hash domain space
+ print out the hash number, the domain space (as the integer input from the user), the percentage threshold, and the
  percentage of the domainspace the hash appears in (truncated to 10 decimal places if possible).
  + these are to be printed comma separated so we can pipe the output to a CSV for analysis. 

## statistical analysis

Once the programs have been ran (I ran mine from 2\*\*10 -> 2\*\*50 because I didn't want to wait any longer and I feel
like that's enough for analysis) it's time to look over the file and run some statistics on when the hash crosses any
certain threshoolds and see if we can't come up with a formula to describe (or approximate) the hash generation that
will have the likelhood to produce a hash collision 