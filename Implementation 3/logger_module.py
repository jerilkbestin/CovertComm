import google.cloud.logging
from datetime import datetime
from datetime import datetime
import os


def logger(time_difference, length):
    # Google Cloud credentials setup
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "/home/ubuntu/spheric-rhythm-414505-6ee966d379b0.json"
    # Instantiates a client
    logging_client = google.cloud.logging.Client()

    # The name of the log to write to
    log_name = 'covertcomm-latency-logs'
    logger = logging_client.logger(log_name)

    # Define the type of log
    log_type = 'send'  # This can be 'send' or 'received', based on your context

    # Structured data to log
    log_entry = {
        'text': f'The latency for message of length {length} is {time_difference} seconds.',
        'length of message': length,
        'Time': time_difference
    }

    # Writes the log entry
    logger.log_struct(log_entry, severity='INFO')

    print("Structured log entry has been written.")