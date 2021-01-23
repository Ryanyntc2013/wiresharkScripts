-- 某人员定位系统 8100 udp端口协议解析wireshark lua脚本

-- 字段	          长度(Bytes)		值	                     备注
-- Type	          1	               0x1C（0xbe）（0x1d）	     消息类型（微信蓝牙定位为0xbe，京信协议为0x1d）
-- Length	      2		           消息体长度
-- MT ID	      6      		                            终端mac地址(微信蓝牙定位为openid，28位，京信协议为8个字节)
-- Sequence ID	  4		                                    基于每个终端的序号
-- GPS Longitude  5		                                    经度（预留）
-- GPS Latitude	  5		                                    纬度（预留）
-- GPS Altitude	  5		                                    高度（预留）
-- X- axle	      3		                                    室内地图相对坐标（X轴）
-- Y- axle	      3		                                    室内地图相对坐标（Y轴）
-- Z- axle	      3		                                    室内地图相对坐标（Z轴）
-- Buildingid	  4		                                    建筑物id
-- Floor	      12		                                楼层
-- IP	          4		                                    定位服务器IP
-- PORT	          4		                                    定位服务器发送数据端口
-- CRC	          2	                                        Calculated value of CRC-16	


-- 函数参考 https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html
-- tvb 参考 https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html

personPos_protocol = Proto("Person",  "PersonPos Protocol")

dtype = ProtoField.uint8("person.type", "Type", base.HEX)
msgLength = ProtoField.uint16("person.length", "msgLen", base.DEC)

mtID = ProtoField.ether("person.mtid", "mtID", "card mac")
seq  = ProtoField.uint32("person.seq", "squence", base.DEC)
x    = ProtoField.uint24("person.x", "x",base.HEX)
y    = ProtoField.uint24("person.y", "y",base.HEX)
ip   = ProtoField.ipv4("person.srvip", "srvip", "server ip addr")
port   = ProtoField.uint32("person.port", "port", base.DEC)
crc =  ProtoField.uint16("person.crc", "crc", base.HEX)
realLen =  ProtoField.uint32("person.realLength", "realLength", base.DEC)

personPos_protocol.fields = {dtype,msgLength, mtID, seq, x,y,ip,port,crc,realLen}

function personPos_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = personPos_protocol.name

  local subtree = tree:add(personPos_protocol, buffer(), "PersonPos Protocol Data")
  subtree:add(dtype, buffer(0,1))
  subtree:add(msgLength, buffer(1,2))
  subtree:add(mtID, buffer(3,6))
  subtree:add(seq, buffer(9,4))
  local xbyte = buffer(28,3):bytes()
  local ybyte = buffer(31,3):bytes()
  local xx = string.format("%x%x.%x",xbyte:get_index(0),xbyte:get_index(1),xbyte:get_index(2))
  local yy = string.format("%x%x.%x",ybyte:get_index(0),ybyte:get_index(1),ybyte:get_index(2))
  subtree:add(x, buffer(28,3)):append_text(" (" .. xx .. ")")
  subtree:add(y, buffer(31,3)):append_text(" (" .. yy .. ")")
  subtree:add(ip, buffer(53,4))
  subtree:add(port, buffer(57,4))
  subtree:add(crc, buffer(61,2))
  subtree:add(realLen, length)
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(8100, personPos_protocol)