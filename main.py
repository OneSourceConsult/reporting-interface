import paho.mqtt.client as mqtt
import threading
import time
import logging
import json
import traceback
import os
import random

# Set up logging
logging.basicConfig(
    level=logging.INFO, ## USE 'DEBUG' for debuging purposes
    format='%(asctime)s [%(levelname)s] %(message)s', 
    handlers=[
        logging.FileHandler("%s_reporting_interface.log"%time.strftime('%d-%m-%Y_%H-%M-%S')),
        logging.StreamHandler()
    ]
)

## Reporting Interface Class
# Available functions
# *on_connect*
#   Used has callback to be invoked upon succesful connection to the MQTT Broker;
# *on_new_anomalies*
#   Invoked by the detection mechanism whenever a new (set of) anomaly(ies) are detected;
#   It updates the local counter of anomalies, considering the anomaly source ip
#   Then, it invokes the *build_attack_reporting_message* so the proper message is created and sent to the MQTT broker
# *get_current_time*
#   Auxiliary function to obtain the current time in milliseconds format
# *build_attack_reporting_message*
#   Invoked by the *on_new_anomalies* function to build the message to be sent to the MQTT Broker
# *on_new_kpis_message
#   Invoked when new KPI values are available to be shared through the network
# *build_kpis_message*
#   Invoked by the *on_new_kpis_message* function to build the message to be sent to the MQTT Broker

class reporting_interface():
    def __init__(self, broker_address, username, password, topic, use_case_id, testbed_id, scenario_id, netApp_id, experiment_id, block_threshold, deployment_name):
        logging.info("Start of reporting_interface mechanism")
        self.record = {}
        self.topic = topic
        self.broker_address = broker_address
        self.client = mqtt.Client()
        self.client.username_pw_set(username, password)
        self.client.connect(self.broker_address)
        self.client.on_connect = self.on_connect
        self.client.subscribe(self.topic)
        self.client.on_message = self.on_message
        client_loop_thread = threading.Thread(target=self.client.loop_forever)
        client_loop_thread.start()
        self.use_case_id = use_case_id
        self.testbed_id = testbed_id
        self.scenario_id = scenario_id
        self.netApp_id = netApp_id
        self.experiment_id = experiment_id
        self.block_threshold = block_threshold
        self.deployment_name = deployment_name
        self.increase_counter = 1

    def on_connect(self,client, userdata, flags, rc):
        if rc == 0:
            logging.info("Connected to External MQTT Broker!")
            self.client.publish(self.topic,"First message sent!")
        else:
            logging.info("Failed to connect, return code %d\n", rc)

    def on_message(self, client, userdata, message):
        logging.info("Received message: %s"%str(message.payload.decode()))

    def on_new_anomalies(self, message):
        try:
            incoming_data = message
            if not 'anomalies' in incoming_data:
                logging.debug('Wrong format message!')
                logging.debug(incoming_data)
                return -1
            incoming_data = json.loads(incoming_data)
            logging.debug("Received data:")
            logging.debug(incoming_data)
            logging.debug(incoming_data['anomalies'])
            anomalies = incoming_data['anomalies']
            detection_details = incoming_data['detection_details']

            for anomaly in anomalies:
                logging.debug('-- current anomaly --')
                logging.debug("\n"+str(anomaly))
                ## Update counter
                source_ip = anomaly['source_ip']
                if source_ip in self.record:
                    self.record[source_ip]["counter"] = self.record[source_ip]["counter"] + self.increase_counter
                    self.record[source_ip]["last_occurrence"] = anomaly['timestamp']
                else:
                    self.record[source_ip] = {}
                    self.record[source_ip]["counter"] = 1
                    self.record[source_ip]["first_occurrence"] = anomaly['timestamp']
                    self.record[source_ip]["last_occurrence"] = anomaly['timestamp']

                logging.info("Detected anomaly from source IP %s, registered amount of anomalies are: %d " % (source_ip,self.record[source_ip]["counter"]))

                attack_message_str = self.build_attack_reporting_message(anomaly,detection_details)
                self.client.publish(self.topic,attack_message_str)
        except Exception as e:
            print('-- Error --')
            print(traceback.format_exc())

    def get_current_time(self):
        # Considering UTC zone; Take a look at 'pytz' library in order to set other timezones

        # Get the current timestamp in seconds (as a float)
        timestamp = time.time()
        # Convert the timestamp to milliseconds (as an integer)
        return int(timestamp * 1000)

    def build_attack_reporting_message(self,anomaly,detection_details):
        attack_message={
                "category" : "hspf",
                "use_case_id": self.use_case_id,
                "testbed_id": self.testbed_id,
                "experiment_id" : self.experiment_id,
                "netApp_id": self.netApp_id,
                "data":{
                    "source_ip":anomaly['source_ip'],
                    "destination_ip":anomaly['destination_ip'],
                    "destination_port":anomaly['destination_port'],
                    "classifier_ip":detection_details['classifier_ip'],
                    "model_id": detection_details['model_id'],
                    "flows_filename": anomaly['flow_filename'],
                    "flows_id" : anomaly['flows_id'],
                    "anomalies_detected" : self.record[anomaly['source_ip']]['counter'],
                    "first_occurrence" : self.record[anomaly['source_ip']]['first_occurrence'],
                    "last_occurrence" : self.record[anomaly['source_ip']]['last_occurrence'],
                    "anomaly_threshold" : self.block_threshold,
                    "reconstruction_error" : detection_details['reconstruction_error'],
                    "comparison_metric" : detection_details['comparison_metric'],
                    "tf_version" : detection_details['tf_version'],
                    "nfstream_version" : detection_details['nfstream_version'],
                },
                "timestamp":self.get_current_time()
            }
        return json.dumps(attack_message)
        
    def on_new_kpis_message(self, is_malicious, value):
        try:
            message=self.build_kpis_message(is_malicious, value)
            self.client.publish(self.topic,message)
        except Exception as e:
            print('-- Error --')
            print(traceback.format_exc())
    
    def build_kpis_message(self, is_malicious,value):
        try:
            attack_message={
                    "category" : "experiment",
                    "testbed_id": self.testbed_id,
                    "netapp_id": self.netApp_id,
                    "data":[{
                        "type": "malicious_flows" if is_malicious else "total_flows",
                        "origin": "main_data_server",
                        "value": value,
                        "network_application": "UC"+str(self.use_case_id),
                        "micro_service": str(self.deployment_name),
                        "hspf_agent_id": "UC"+str(self.use_case_id) + "-" + str(self.deployment_name),                    
                        "timestamp":self.get_current_time(),
                    }],
                }
            return json.dumps(attack_message)
        except Exception as e:
            logging.error(">> Error at %s")
            print(traceback.format_exc())

def validate_reporting_interface():
    logging.info("Start of validation function")

    broker_address = '10.1.1.17'
    broker_username = '<username>'
    broker_password = '<password>'
    broker_topic = '/test'
    use_case_id = 1
    deployment_name = 'Application A'
    testbed_id = 1
    scenario_id = 1
    netApp_id = 1
    experiment_id = 1
    block_threshold = 4
    reporting_interface_instance = reporting_interface(broker_address, broker_username, broker_password, broker_topic, use_case_id, testbed_id, scenario_id, netApp_id, experiment_id, block_threshold, deployment_name)

    time.sleep(5)

    message_anomalies = {
        "anomalies": [{
            "source_ip": "172.24.0.10",
            "destination_ip": "10.16.1.2",
            "destination_port": "45749",
            "flow_filename": "/Temp/flow_20231101.csv",
            "flows_id": "3401",
            "flow_json": "[3401,172.24.0.10,443,10.16.1.2,45749,6,1,0,97,97,97.0,0.0,0,0,0.0,0.0,0.0,0.0,0,0,0.0,0.0,0,0,1,0,0,0,1]",
            "timestamp": reporting_interface_instance.get_current_time()
        },
        {
            "source_ip": "172.24.0.11",
            "destination_ip": "10.16.1.2",
            "destination_port": "45746",
            "flow_filename": "/Temp/flow_20231101.csv",
            "flows_id": "3455",
            "flow_json": "[3455,172.24.0.11,443,10.16.1.2,45746,6,1,0,97,97,97.0,0.0,0,0,0.0,0.0,0.0,0.0,0,0,0.0,0.0,0,0,1,0,0,0,1]",
            "timestamp": reporting_interface_instance.get_current_time()
        }
        ],
        "detection_details": {
            "classifier_ip": "10.16.1.10",
            "flow_features": "List of Features used for Classification",
            "model_id": "deployment_name_v0.0",
            "reconstruction_error": "0.02",
            "comparison_metric": "Mean Squared Error",
            "tf_version": "v2.0.1",
            "nfstream_version": "6.5.3", 
            "timestamp": reporting_interface_instance.get_current_time()              
        }
    }

    previous = False
    while(True):
        reporting_interface_instance.on_new_anomalies(json.dumps(message_anomalies))
        time.sleep(5)
        value = random.randint(1,1500) # Simulating the value of malicious and normal flows detected
        previous = not previous # Alternating between report on malicious and normal flows
        reporting_interface_instance.on_new_kpis_message(previous, value)
        time.sleep(10)


if __name__ == "__main__":
    validate_reporting_interface()

