#!/bin/bash

for f in *.cpp; do 
	sed -i '' 's/.cpp/.cc/g' f   	
# mv -- "$f" "${f%.cpp}.cc"
done
