# /bin/sh

echo "Clean up data generated when execute scripts..."
rm -rf conf/node1/data/*
rm -rf conf/node1/katzenmint
echo "{
  \"height\": \"0\",
  \"round\": 0,
  \"step\": 0
}" > conf/node1/data/priv_validator_state.json

rm -rf conf/node2/data/*
rm -rf conf/node2/katzenmint
echo "{
  \"height\": \"0\",
  \"round\": 0,
  \"step\": 0
}" > conf/node2/data/priv_validator_state.json

rm -rf conf/node3/data/*
rm -rf conf/node3/katzenmint
echo "{
  \"height\": \"0\",
  \"round\": 0,
  \"step\": 0
}" > conf/node3/data/priv_validator_state.json
echo "Cleaned up!"