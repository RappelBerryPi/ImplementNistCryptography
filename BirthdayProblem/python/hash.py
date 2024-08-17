import sys
import datetime

domain_space = 2**32
display_domain_space = "32"
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
for i in range(domain_space, 1, -1):
    this_percentage = i / domain_space
    current_percentage *= this_percentage
    if (current_percentage < flipped_percentage):
        hash_spot_past_threshold = (domain_space - i) + 1
        break
finish = datetime.datetime.now()

percentage_of_domain_space = hash_spot_past_threshold / domain_space
run_time = finish - start
print("{}, {}, {}, {:.20f}, {}".format(hash_spot_past_threshold, display_domain_space, display_percentage, percentage_of_domain_space, run_time))