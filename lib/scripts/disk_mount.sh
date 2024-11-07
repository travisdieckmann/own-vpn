#!/usr/bin/env bash
DEVICE_PATH=$1
MOUNT_POINT=$2

retries=60
while ((retries > 0)); do
  for blkdev in $(nvme list | awk '/^\/dev/ { print $1 }'); do
    mapping=$(nvme id-ctrl --raw-binary "${blkdev}" | cut -c3073-3104 | tr -s ' ' | sed 's/ $//g')
    if [ ${mapping} = ${DEVICE_PATH} ]; then
      echo "Found $device on $blkdev"
      if ! file -s ${blkdev} | grep -q XFS; then
        echo "Device empty, formatting..."
        mkfs -t xfs ${blkdev}
      fi
      echo "Mounting..."
      mkdir -p ${MOUNT_POINT}
      uuid=$(blkid -s UUID -o value ${blkdev})
      
      if grep -Fxq "${uuid}" /etc/fstab; then
        echo "UUID already in fstab!"
      else
        echo "Adding mount to fstab! UUID=\"${uuid}\""
        echo "UUID=\"${uuid}\"	${MOUNT_POINT}	xfs	defaults,nofail" >> /etc/fstab
      fi
      
      mount UUID="${uuid}"
      echo "Done!"
      break 2
    fi
  done
  echo "Could not find drive, trying again in 1 second."
  sleep 1
    ((retries --))
done