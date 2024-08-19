FROM ubuntu:20.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    suricata \
    python3-pip \
    wget \
    tar

# Copy project files
COPY . /IntrusionDetectionSystem/

# Set up Python environment
RUN pip3 install -r /IntrusionDetectionSystem/requirements.txt

# Run the setup script
RUN chmod +x /IntrusionDetectionSystem/scripts/setup.sh
CMD ["/IntrusionDetectionSystem/scripts/setup.sh"]
