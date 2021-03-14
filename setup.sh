# /bin/sh
if ! command -v tendermint &> /dev/null
then
    echo "No tendermint in PATH, please install tendermint first."
    exit
fi
TMHOME=`pwd`/chain tendermint init