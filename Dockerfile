# Use an official Ubuntu image as a parent image
FROM ubuntu:20.04

# Set the environment variable DEBIAN_FRONTEND to noninteractive
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    g++ \
    libssl-dev \
    libjsoncpp-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Create a build directory
# RUN mkdir build
# WORKDIR /app/build

# Default command to run a shell
CMD ["/bin/bash"]

# Run cmake to configure the build environment
# RUN cmake ..    

# Build the project
# RUN make

# Specify the command to run the executable
# CMD ["./DistributedChat"]
