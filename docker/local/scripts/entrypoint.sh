# /bin/ash

echo ""
echo "Update Voting TrustOptions..."
echo ""

until /go/bin/updateconfig -f /conf/katzenpost.toml; do
  >&2 echo "Katzenmint is unavailable - sleeping 1 second"
  sleep 1
done

echo ""
echo "Start Meson Server"
echo ""
/go/bin/server -f /conf/katzenpost.toml