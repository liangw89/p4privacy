import random
tmp = """
hdr.ipv6.src_addr[31:31] = copy1_1.get(ig_md.c1[7:7]);
hdr.ipv6.src_addr[30:30] = copy1_2.get(ig_md.c1[6:6]);
hdr.ipv6.src_addr[29:29] = copy1_3.get(ig_md.c1[5:5]);
hdr.ipv6.src_addr[28:28] = copy1_4.get(ig_md.c1[4:4]);
hdr.ipv6.src_addr[27:27] = copy1_5.get(ig_md.c1[3:3]);
hdr.ipv6.src_addr[26:26] = copy1_6.get(ig_md.c1[2:2]);
hdr.ipv6.src_addr[25:25] = copy1_7.get(ig_md.c1[1:1]);
hdr.ipv6.src_addr[24:24] = copy1_8.get(ig_md.c1[0:0]);

hdr.ipv6.src_addr[23:23] = copy1_9.get(ig_md.c2[7:7]);
hdr.ipv6.src_addr[22:22] = copy1_10.get(ig_md.c2[6:6]);
hdr.ipv6.src_addr[21:21] = copy1_11.get(ig_md.c2[5:5]);
hdr.ipv6.src_addr[20:20] = copy1_12.get(ig_md.c2[4:4]);
hdr.ipv6.src_addr[19:19] = copy1_13.get(ig_md.c2[3:3]);
hdr.ipv6.src_addr[18:18] = copy1_14.get(ig_md.c2[2:2]);
hdr.ipv6.src_addr[17:17] = copy1_15.get(ig_md.c2[1:1]);
hdr.ipv6.src_addr[16:16] = copy1_16.get(ig_md.c2[0:0]);

hdr.ipv6.src_addr[15:15] = copy1_17.get(ig_md.c3[7:7]);
hdr.ipv6.src_addr[14:14] = copy1_18.get(ig_md.c3[6:6]);
hdr.ipv6.src_addr[13:13] = copy1_19.get(ig_md.c3[5:5]);
hdr.ipv6.src_addr[12:12] = copy1_20.get(ig_md.c3[4:4]);
hdr.ipv6.src_addr[11:11] = copy1_21.get(ig_md.c3[3:3]);
hdr.ipv6.src_addr[10:10] = copy1_22.get(ig_md.c3[2:2]);
hdr.ipv6.src_addr[9:9] = copy1_23.get(ig_md.c3[1:1]);
hdr.ipv6.src_addr[8:8] = copy1_24.get(ig_md.c3[0:0]);

hdr.ipv6.src_addr[7:7] = copy1_25.get(ig_md.c4[7:7]);
hdr.ipv6.src_addr[6:6] = copy1_26.get(ig_md.c4[6:6]);
hdr.ipv6.src_addr[5:5] = copy1_27.get(ig_md.c4[5:5]);
hdr.ipv6.src_addr[4:4] = copy1_28.get(ig_md.c4[4:4]);
hdr.ipv6.src_addr[3:3] = copy1_29.get(ig_md.c4[3:3]);
hdr.ipv6.src_addr[2:2] = copy1_30.get(ig_md.c4[2:2]);
hdr.ipv6.src_addr[1:1] = copy1_31.get(ig_md.c4[1:1]);
hdr.ipv6.src_addr[0:0] = copy1_32.get(ig_md.c4[0:0]);

hdr.ipv6.src_sub[31:31] = copy1_33.get(ig_md.r1[7:7]);
hdr.ipv6.src_sub[30:30] = copy1_34.get(ig_md.r1[6:6]);
hdr.ipv6.src_sub[29:29] = copy1_35.get(ig_md.r1[5:5]);
hdr.ipv6.src_sub[28:28] = copy1_36.get(ig_md.r1[4:4]);
hdr.ipv6.src_sub[27:27] = copy1_37.get(ig_md.r1[3:3]);
hdr.ipv6.src_sub[26:26] = copy1_38.get(ig_md.r1[2:2]);
hdr.ipv6.src_sub[25:25] = copy1_39.get(ig_md.r1[1:1]);
hdr.ipv6.src_sub[24:24] = copy1_40.get(ig_md.r1[0:0]);

hdr.ipv6.src_sub[23:23] = copy1_41.get(ig_md.r2[7:7]);
hdr.ipv6.src_sub[22:22] = copy1_42.get(ig_md.r2[6:6]);
hdr.ipv6.src_sub[21:21] = copy1_43.get(ig_md.r2[5:5]);
hdr.ipv6.src_sub[20:20] = copy1_44.get(ig_md.r2[4:4]);
hdr.ipv6.src_sub[19:19] = copy1_45.get(ig_md.r2[3:3]);
hdr.ipv6.src_sub[18:18] = copy1_46.get(ig_md.r2[2:2]);
hdr.ipv6.src_sub[17:17] = copy1_47.get(ig_md.r2[1:1]);
hdr.ipv6.src_sub[16:16] = copy1_48.get(ig_md.r2[0:0]);

hdr.ipv6.src_sub[15:15] = copy1_49.get(ig_md.r3[7:7]);
hdr.ipv6.src_sub[14:14] = copy1_50.get(ig_md.r3[6:6]);
hdr.ipv6.src_sub[13:13] = copy1_51.get(ig_md.r3[5:5]);
hdr.ipv6.src_sub[12:12] = copy1_52.get(ig_md.r3[4:4]);
hdr.ipv6.src_sub[11:11] = copy1_53.get(ig_md.r3[3:3]);
hdr.ipv6.src_sub[10:10] = copy1_54.get(ig_md.r3[2:2]);
hdr.ipv6.src_sub[9:9] = copy1_55.get(ig_md.r3[1:1]);
hdr.ipv6.src_sub[8:8] = copy1_56.get(ig_md.r3[0:0]);

hdr.ipv6.src_sub[7:7] = copy1_57.get(ig_md.r4[7:7]);
hdr.ipv6.src_sub[6:6] = copy1_58.get(ig_md.r4[6:6]);
hdr.ipv6.src_sub[5:5] = copy1_59.get(ig_md.r4[5:5]);
hdr.ipv6.src_sub[4:4] = copy1_60.get(ig_md.r4[4:4]);
hdr.ipv6.src_sub[3:3] = copy1_61.get(ig_md.r4[3:3]);
hdr.ipv6.src_sub[2:2] = copy1_62.get(ig_md.r4[2:2]);
hdr.ipv6.src_sub[1:1] = copy1_63.get(ig_md.r4[1:1]);
hdr.ipv6.src_sub[0:0] = copy1_64.get(ig_md.r4[0:0]);


"""
def perm1():
	ks = []
	vs = []
	for l in tmp.split("\n"):
		if not l: continue
		k, v = l.split("=")
		ks.append(k)
		vs.append(v.strip())

	l = list(xrange(len(vs)))

	rks = []
	rvs = []
	print "set_final_ip + set_final_sub:"
	for i in xrange(len(ks)):
		
		vt = vs[l[i]].split("(")[1].replace(");", "")
		pfx = vt.split("[")[0].split(".")[1]
		idx = int(vt.split("[")[1].split(":")[0])
		if pfx == "c4" or pfx == "r4":
			idx = idx
		if pfx == "c3" or pfx == "r3":
			idx = 8 + idx
		if pfx == "c2" or pfx == "r2":
			idx = 16 + idx
		if pfx == "c1" or pfx == "r1":
			idx = 24 + idx
		if pfx.startswith("c"):
			pfx = "ig_md.new_ip"
		else:
			pfx = "ig_md.new_rnd1"
		rks.append(pfx)
		rvs.append(idx)
		print "%s= %s" % (ks[i], vs[l[i]].replace("copy1", "copy1")) # , pfx, idx
		
	print "copy_ip_r:"
	out = []
	for i in xrange(len(rks)):
		# print rks[i], rvs[i], vs[i]
		ts = "%s[%s:%s] = %s" % (rks[i], rvs[i], rvs[i], vs[i].replace("copy1", "copy2"))
		out.append(ts)

	for i in list(xrange(32))[::-1]:
		for it in out:
			if it.startswith("ig_md.new_ip[%s:" % i):
				print it
	print "gen_rnd:"
	for i in list(xrange(32))[::-1]:
		for it in out:
			if it.startswith("ig_md.new_rnd1[%s:" % i):
				print it

def perm2():
	vs = []
	ks = []
	for l in tmp.split("\n"):
		if not l: continue
		k, v = l.split("=")
		ks.append(k)
		vs.append(v.strip().strip(";"))
	l = list(xrange(32 + 32))
	random.shuffle(l)

	p1 = []
	p2 = []
	rp1 = []
	rp2 = []
	for i in xrange(len(l)):
		tk = ks[i]
		tv = vs[l[i]].replace("copy1", "copy3").strip()
		s = "%s= %s;" % (tk, tv)
		if tk.startswith("hdr.ipv6.src_addr"):
			p1.append(s)
		else:
			p2.append(s)

	rl = []
	for i in xrange(len(l)):
		rl.append(l.index(i))

	print 

	for i in xrange(len(l)):
		tk = ks[i].replace("hdr.ipv6.src_addr", "ig_md.new_ip").replace("hdr.ipv6.src_sub", "ig_md.new_rnd1")
		tv = vs[rl[i]].replace("copy1", "copy4")
		s = "%s= %s;" % (tk, tv)
		if tk.startswith("ig_md.new_ip"):
			rp1.append(s)
		else:
			rp2.append(s)

	print "action p1(){\n" + "\n".join(p1) + "\n}"
	print "action p2(){\n" + "\n".join(p2) + "\n}"
	print "action rp1(){\n" + "\n".join(rp1) + "\n}"
	print "action rp2(){\n" + "\n".join(rp2) + "\n}"


perm1()
perm2()