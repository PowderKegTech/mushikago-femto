echo "Kill the MUSHIKAGO process..."
PID=`ps aux | grep "python3" | grep "main.py" | grep "root" | awk '{print $2}'`
for i in ${PID}; do
  echo "MUSHIKAGO process(PID) = "$i
  kill -9 $i
done

echo "Kill the msfrpcd process..."
PID=`ps aux | grep "msfrpcd" | grep -v "color" | awk '{print $2}'`
for i in ${PID}; do
  echo "msfrpcd process(PID) = "$i
  kill -9 $i
done

