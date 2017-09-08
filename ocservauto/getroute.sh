#!/bin/bash
[ -e result.txt ]
rm result.txt
operation(){
    result=$(nslookup $domain $dns | awk '/^Address: / { print $2 }') && echo "$result $domain $dns" >> result.txt
}
while read -r domain
do
tmp_fifofile=/tmp/$$.fifo
#echo $tmp_fifofile
mkfifo $tmp_fifofile # 新建一个fifo的管道文件
exec 6<>$tmp_fifofile # 绑定fd6
rm $tmp_fifofile
# 这里是向管道添加了$thread个空行
THREAD=500 # 线程数，可以改变
for i in $(seq 0 $THREAD);do
    echo
done >&6
CONFIG_FILE=dns.txt
# 修改这个脚本到生成环境，主要是修改operation和CONFIG_FILE配置
# 每次读取一行数据
while read dns
do
    # 一个read -u6命令执行一次，就从fd6中减去一个回车符，然后向下执行，
    # fd6 中没有回车符的时候，就停在这了，从而实现了线程数量控制
    read -u6
    {
       # 操作成功，记录到成功日志,修改echo
       # 操作失败，记录到错误日志
       operation && echo "$domain $dns success" || echo "$domain $dns error"
       # 当进程结束以后，再向fd6中加上一个回车符，即补上了read -u6减去的那个
       echo  >&6
    } & # 后台执行，这里的 &是非常重要的，同时有$THREAD个后台进程 
done < ${CONFIG_FILE}
wait # 等待所有的后台子进程结束
exec 6>&- # 关闭df6
done < domain.txt
