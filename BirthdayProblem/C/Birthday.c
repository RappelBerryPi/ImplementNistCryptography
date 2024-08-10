#include <stdlib.h>

int main(int argc, char *argv[]) {

    /* this is the number of days in a year (ignoring leap years)*/
    long long possibleBirthdays = 365;
    /* 
       this is the percentage that we would like to be at when that when we introduce a new person, they have this
       likely of a percentage to match with someone else in the room
    */
    int displayPercentage = 50;
    if (argc == 2) {
        displayPercentage = atoi(argv[1]);
    }
    double targetPercentage = displayPercentage / 100.0;

    /*
       because we're counting down from a probability of 100%, we need to flip the percentage and cross that threshold instead.
    */
    double flippedPercentage = 1.0 - targetPercentage;

    /* this will hold the answer of who it is that breaks our percentage barrier */
    long long newPerson = 0;

    double currentPercentage = 1.0;
    double doublePossibleBirthdays = (double) possibleBirthdays;
    for (int i = possibleBirthdays; i > 0; i--) {
        /* the new person will have this percentage to multiply into the probability when they walk into the room */
        double introducedPercentage = i / doublePossibleBirthdays;

        /* let's update our percentage with the new person */
        currentPercentage = introducedPercentage * currentPercentage;

        /* now let's check to see if we're past our threshold*/
        if (currentPercentage < flippedPercentage) {
            newPerson = (possibleBirthdays - i) + 1;
            break;
        }
    }

    /* now that we've found our person, let's do some statistics */

    /* what percentage of the amount of birthday's were covered before we reached this point? */
    double percentageOfTotalBirthdays = (newPerson / doublePossibleBirthdays) * 100;

    printf("The %i person (and every person after) gives at least a %i%% chance that they will share a birthday with someone else\n", newPerson, displayPercentage);
    printf("This is %f%% of the total number of possible birthdays\n", percentageOfTotalBirthdays);
    return 0;
}