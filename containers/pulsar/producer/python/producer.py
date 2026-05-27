import pulsar
client = pulsar.Client('pulsar://pulsar:6650')
producer = client.create_producer(topic='in',
                                  send_timeout_millis=10000)
producer.send(("10,20").encode('utf-8'))
client.close()