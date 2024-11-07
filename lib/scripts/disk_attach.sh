#!/usr/bin/env bash
export AWS_DEFAULT_REGION=$1
VOLUME_ID=$2
DEVICE_PATH=$3

INSTANCE_ID=$(ec2-metadata --quiet -i)
ATTACHED_INSTANCE_ID=$(aws --region ${AWS_DEFAULT_REGION} ec2 describe-volumes --volume-ids ${VOLUME_ID}|jq -r '.Volumes[0].Attachments[0].InstanceId')

function instance_is_running() {
    echo $(aws ec2 describe-instances --instance-ids $1 | jq -r '.Reservations[0].Instances[0].State.Name')
}
if [ "${ATTACHED_INSTANCE_ID}" == "null" ]; then
    echo "Volume is not attached..."
else
    if [ "${INSTANCE_ID}" == "${ATTACHED_INSTANCE_ID}" ]; then
        echo "Already attached to this instance!"
        exit 0
    else
        echo "Volume is attached to instance: ${ATTACHED_INSTANCE_ID}"
        
        ec2_state="$(instance_is_running $ATTACHED_INSTANCE_ID)"
        while [ true ]; do
            [ "${ec2_state}" == "stopped" ] && break
            [ "${ec2_state}" == "terminated" ] && break
            
            echo "Instance: ${ATTACHED_INSTANCE_ID} is "${ec2_state}". Waiting..."
            sleep 1
            ec2_state="$(instance_is_running $ATTACHED_INSTANCE_ID)"
        done
        aws ec2 detach-volume --volume-id ${VOLUME_ID}
    fi
fi
retries=10
while ((retries > 0)); do
    aws ec2 attach-volume --instance-id ${INSTANCE_ID} --volume-id ${VOLUME_ID} --device ${DEVICE_PATH} && break
    echo "something went wrong, let's wait 3 seconds and retry"
    sleep 3
    ((retries --))
done