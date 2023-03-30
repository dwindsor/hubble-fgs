set style fill solid

set multiplot
set multiplot layout 2,1

set key outside

set yrange [0:*]
set ytics nomirror
set y2range [0:100]
set y2tics
set y2label "CPU %"

rrbase=system("head -1 rr.dat | awk '{print $3}'")
rrlobase=system("head -1 rrlo.dat | awk '{print $3}'")
rrfonts= (rrbase > rrlobase ? rrbase : rrlobase)
rrsign= (rrbase > rrlobase ? 1 : -1)

set ylabel "req/sec"
set title "TCP RR Benchmark"
plot "rr.dat" using 3:xtic(2) with histograms title "rr-veth",      \
	'' u ($0-0.2*rrsign):($3 + (rrfonts * 0.08)):(sprintf("%3.0f\%", (100 * (($3 - rrbase)  / rrbase)))) w labels font "Times,8" notitle, \
     "" using ($1-0.12):($4 + $5) axes x1y2 title "rr-veth-CPU", \
     "rrlo.dat" using 3 with histograms title "rr-lo",              \
     '' u ($0+0.2*rrsign):($3 + (rrfonts * 0.08)):(sprintf("%3.0f\%", (100 * (($3 - rrlobase)  / rrlobase)))) w labels font "Times,8" notitle, \
     "" using ($1+0.12):($4 + $5) axes x1y2 title "rr-lo-CPU"

streambase=system("head -1 stream.dat | awk '{print $3}'")
streamlobase=system("head -1 streamlo.dat | awk '{print $3}'")
streamfonts= (streambase > streamlobase ? streambase : streamlobase)
streamsign= (rrbase > rrlobase ? 1 : -1)

set ylabel "Bandwidth (Mbps)"
set title "TCP Stream Benchmark"
plot "stream.dat" using 3:xtic(2) with histograms title "stream-veth", \
	'' u ($0-0.2*streamsign):($3 + (streamfonts * 0.08)):(sprintf("%3.0f\%", (100 * (($3 - streambase)  / streambase)))) w labels font "Times,8" notitle, \
     "" using ($1-0.12):($4 + $5) axes x1y2 title "stream-veth-CPU",   \
     "streamlo.dat" using 3 with histograms title "stream-lo",         \
     '' u ($0+0.2*streamsign):($3 + (streamfonts * 0.08)):(sprintf("%3.0f\%", (100 * (($3 - streamlobase)  / streamlobase)))) w labels font "Times,8" notitle, \
     "" using ($1+0.12):($4 + $5) axes x1y2 title "stream-lo-CPU"
