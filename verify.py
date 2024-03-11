
	def verify(self):
		self.pull.up("Validating Received Captures..."); time.sleep(2)
		for pkt in self.pkts:
			self.check(pkt)
			if 0 not in self.__POLS:
				self.__POL = True; break
		if self.__POL:
			if self.verbose:
				self.pull.info("EAPOL %s (%s) %s<>%s %s (%s) %s[RECEIVED]%s" % (self.bssid.replace(':','').upper(), self.pull.DARKCYAN+org(self.bssid).org+self.pull.END, self.pull.RED, self.pull.END, \
															self.cl.replace(':','').upper(), self.pull.DARKCYAN+org(self.cl).org+self.pull.END, self.pull.YELLOW, self.pull.END))
			else:
				self.pull.info("EAPOL %s %s<>%s %s %s[RECEIVED]%s" % (self.bssid.replace(':','').upper(), self.pull.RED, self.pull.END, \
															self.cl.replace(':','').upper(), self.pull.YELLOW, self.pull.END))
			return True
		else:
			return False

	def check(self, pkt):
		fNONCE = "0000000000000000000000000000000000000000000000000000000000000000"
		fMIC = "00000000000000000000000000000000"

		if pkt.haslayer(EAPOL):
			__sn = pkt[Dot11].addr2
			__rc = pkt[Dot11].addr1
			to_DS = pkt.getlayer(Dot11).FCfield & 0x1 !=0
			from_DS = pkt.getlayer(Dot11).FCfield & 0x2 !=0

			if from_DS == True:
				nonce = binascii.hexlify(pkt.getlayer(Raw).load)[26:90]
				mic = binascii.hexlify(pkt.getlayer(Raw).load)[154:186]
				if nonce != fNONCE and mic == fMIC:
					self.bssid = __sn; self.cl = __rc
					self.__POLS[0] = pkt
				elif __sn == self.bssid and __rc == self.cl and nonce != fNONCE and mic != fMIC:
					self.__POLS[2] = pkt
			elif to_DS == True:
				nonce = binascii.hexlify(pkt.getlayer(Raw).load)[26:90]
				mic = binascii.hexlify(pkt.getlayer(Raw).load)[154:186]
				if __sn == self.cl and __rc == self.bssid and nonce != fNONCE and mic != fMIC:
					self.__POLS[1] = pkt
				elif __sn == self.cl and __rc == self.bssid and nonce == fNONCE and mic != fMIC:
					self.__POLS[3] = pkt
