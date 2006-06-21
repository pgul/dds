
# defined variables:
# $by ("bynone", "bysrc", "bydst", "bysrcdst", "bydstport")
# $cp ("bps", "pps", "udp pps", "icmp pps", "syn pps")
# $in (0 or 1)
# $ip (x.x.x.x/n (for bynone), x.x.x.x, x.x.x.x:nn, x.x.x.x->x.x.x.x)
# $count (current pps or bps)
# $interval
# $limit, $safelimit
# $id (alarm identifier, uniq string)
# $inhibited (0 or 1, is more specific alarm active now)

sub alarm_start
{
}

sub alarm_finish
{
}

sub alarm_cont
{
}

sub on_exit
{
}
