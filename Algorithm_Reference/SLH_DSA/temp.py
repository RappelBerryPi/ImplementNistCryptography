from abc import ABC,abstractmethod
class Person(ABC):
    def __init__(self, fname, lname):
        self.firstname = fname
        self.lastname = lname

    @abstractmethod
    def printname(self):
        pass

class Student(Person):
    def printname(self):
        print(self.firstname, self.lastname)
    
def getStudent() -> Person:
    return Student("john", "doe")

x = getStudent()
x.printname()