import sys
import datetime

domain_space = 365
display_domain_space = "365"
display_percentage = 50

if (len(sys.argv) > 1):
    display_percentage = int(sys.argv[1])

if (len(sys.argv) > 2):
    domain_space = 2**(int(sys.argv[2]))
    display_domain_space = sys.argv[2]

target_percentage = display_percentage / 100

# because we're counting down from a probability of 100%, we need to flip the percentage and cross that threshold instead.
flipped_percentage = 1 - target_percentage


hash_spot_past_threshold = 0
current_percentage = 1

start = datetime.datetime.now()
this_percentage = (domain_space - 1) / domain_space
while (current_percentage >= flipped_percentage):
    hash_spot_past_threshold += 1
    current_percentage *= this_percentage
finish = datetime.datetime.now()

percentage_of_domain_space = hash_spot_past_threshold / domain_space
run_time = finish - start
print("{}, {}, {}, {:.20f}, {}".format(hash_spot_past_threshold, display_domain_space, display_percentage, percentage_of_domain_space, run_time))


# note that at around the 2**20 -> 2**25 mark, it becomes painfully obvious that to reach a 50 percent probability it's
# going to take around  0.69314718246459960938 * the domain space


# others are similar:
# + 10
#   + 0.10536051541566848755
# + 25
#   + 0.28768207877874374390
# + 50
#   + 0.69314718246459960938
# + 63
#   + 0.99425220489501953125

# after 63% the numbers become funny enough that by doing the math above, you have to reach essentially the end of the
# domain space before you could reach the percentage we want to cross. Which means that we have an extremely high chance
# that the generation of a hash will probably not be our hash if things are truly random so finding a collision gives at
# best a 63% chance once you've exausted the entire domain space.


# This makes sense when you think about the randomly generated problem space such as people walking into a room, If
# people were to walk into a room, you have about 43 people until a singular birthday colision of some kind is found ,
# but by picking exactly one birthday, you have to get 1679 people in a room to have a 99% chance that a person with the
# same birthday has walked in. This is because (randomly) a person has a 1/365 chance that they share a birthday each
# time, but they also have a 364/365 chance that they do not (pretending leap years do not exist). 

# of course, you could calculate based upon the perceived favorable event in which a person does share a birthday vs the
# number of total events. 

# for example, the chance that someone walks in with a birthday is 1/1, but let's pick that birthday as jan-1. then
# every person that walks in after that always has a 1/365 chance of having that same birthday. because of this, the
# compounding probability that the next (random) person walking in doesn't share a birthday is the only way to do this
# compounding probability