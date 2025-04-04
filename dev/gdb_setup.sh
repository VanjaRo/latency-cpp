# Inside the container shell (/app directory)
mkdir -p /dev/shm/pcap_proj_gdb # Use a distinct prefix for safety
BUFFER_PREFIX="/dev/shm/pcap_proj_gdb/debug_buffer"
touch "${BUFFER_PREFIX}_input_header"
touch "${BUFFER_PREFIX}_input_buffer"
touch "${BUFFER_PREFIX}_output_header"
touch "${BUFFER_PREFIX}_output_buffer"
BUFFER_SIZE=2097152 # Use the same size as before or from logs
META_PATH="./data/public1.meta" # Adjust if needed

gdb --args ./solution/build/solution \
            "${BUFFER_PREFIX}_input_header" \
            "${BUFFER_PREFIX}_input_buffer" \
            "${BUFFER_PREFIX}_output_header" \
            "${BUFFER_PREFIX}_output_buffer" \
            "${BUFFER_SIZE}" \
            "${META_PATH}"