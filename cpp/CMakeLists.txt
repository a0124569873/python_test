#project name  
PROJECT(test_math)  
#head file path  
INCLUDE_DIRECTORIES(  
include  
)  
#source directory  
AUX_SOURCE_DIRECTORY(src DIR_SRCS)  
#set environment variable  
SET(TEST_MATH  
${DIR_SRCS}  
)  
#add executable file  
ADD_EXECUTABLE(../bin/bin ${TEST_MATH})  
#add link library  
TARGET_LINK_LIBRARIES(../bin/bin m)  
