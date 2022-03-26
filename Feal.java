package com.jstevenperry.learn.java;

import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

//Before running program please place known.txt provided in a same folder or change the file path because this program is reading the data from that file
//Reference code https://github.com/Twice22/feal-4-differential-cryptanalysis/blob/master/cryptaFEAL-4.java
// For K0_prime there are 16 results and for final K0 i have 1020 results and another equation produce 2040 results and narrow down results there are 156 results.


public class Feal {
	
	public static ArrayList<String> text = new ArrayList<String>(); // array list contain full text from file 
	public static ArrayList<String> plaintext = new ArrayList<String>(); // array list contain plain text only 
	public static ArrayList<String> ciphertext = new ArrayList<String>(); // array list contain cipher text only
	public static ArrayList<String> key = new ArrayList<String>(); // array list with final k0 values
	public static ArrayList<String> keyguess2 = new ArrayList<String>(); // array list with guess 2 for k0 values
	public static ArrayList<String> key1 = new ArrayList<String>(); // middle bit guess for k1
	public static ArrayList<String> key1_final1 = new ArrayList<String>(); // 32 bit guess for k1
	public static ArrayList<String> key1_final2 = new ArrayList<String>(); // 32 bit values equation 2 for k1
	public static ArrayList<String> key2 = new ArrayList<String>(); // middle bit guess for k2
	public static ArrayList<String> key2_final1 = new ArrayList<String>(); // 32 bit guess for k2
	public static ArrayList<String> key2_final2 = new ArrayList<String>(); // 32 bit values equation 2 for k2
	
	// function to read data from the file
	public static void read_file() throws Exception 
	{
		
		
		try {
		      File myObj = new File("known.txt");
		      Scanner myReader = new Scanner(myObj);
		      while (myReader.hasNextLine()) {
		        String data = myReader.nextLine();
		        text.add(data);
		        //String substr = data.substring(12,28);
		        
		      }
		      myReader.close();   
		    } catch (FileNotFoundException e) {
		      System.out.println("An error occurred.");
		      e.printStackTrace();
		    }		
	}
	
	//strip data and only extract required data and store them in two different array list of plaintext and ciphertext
	public static void stripdata() throws Exception
	{
		int i=0;
		for(i=0;i<599;i++)
		{
			if(i == 0 | (i%3 ==0))
            {
            	String full = text.get(i);
            	String strip_1 = full.substring(12,28);
            	plaintext.add(strip_1);
            	//System.out.println(strip_1);
            	
				
				
				
			}
			else if(i == 1 | ((i+2)%3 == 0))
			{
				String full = text.get(i);
            	String strip_2 = full.substring(12,28);
            	ciphertext.add(strip_2);
				//System.out.println(text.get(i));
			}
		}
		
	}
	
	//  we can say convert byte array to respective hex value 
		private static String btoh (byte[] value) {
			BigInteger sh256 = new BigInteger(1, value);
			String valueHex = String.format("%0" + (value.length << 1) + "X", sh256); // this is length of value in hex (X)
			return valueHex;
		}
		
		
		// this function takes hex values from file and convert into real hex digits for confirmation
		private static byte[] htob (String hex_value) {
			int size = hex_value.length();
			byte[] res = new byte[ size / 2];
			for (int i = 0 ; i < size ; i+= 2) {
				res [i / 2] = (byte) ((Character.digit(hex_value.charAt(i), 16) << 4)
	                    + Character.digit(hex_value.charAt(i+1), 16));
			}
			return res;
		}
		
		//algorithm function for rounds rot2,g0,g1,F
		static byte rot2(byte x) {
	        return (byte)(((x&255)<<2)|((x&255)>>>6));
	    }
	    
	    static byte g0(byte a,byte b) {
	        return rot2((byte)((a+b)&255));
	    }

	    static byte g1(byte a,byte b) {
	        return rot2((byte)((a+b+1)&255));
	    }
	    
	   /*static int pack(byte[] b,int startindex) {
	       return ((b[startindex+3]&255) |((b[startindex+2]&255)<<8)|((b[startindex+1]&255)<<16)|((b[startindex]&255)<<24));
	    }

	    static void unpack(int a,byte[] b,int startindex) {
	       
	        b[startindex]=(byte)(a>>>24);
	        b[startindex+1]=(byte)(a>>>16);
	        b[startindex+2]=(byte)(a>>>8);
	        b[startindex+3]=(byte)a;
	    }*/
	    
	    
	    // Used to join y0,y1,y2,y3 from F to a single word
	    public static byte[] concat(byte[] a, byte[] b){
	        int length = a.length + b.length;
	        byte[] res = new byte[length];
	        System.arraycopy(a, 0, res, 0, a.length);
	        System.arraycopy(b, 0, res, a.length, b.length);
	        return res;
	    }

	    public static byte[] F(byte[] inp) {
			byte y1 =  g1( (byte)(inp[0]^inp[1]), (byte) (inp[2]^inp[3]));
			byte y2 =  g0( y1, (byte) (inp[2]^inp[3]));
			
			byte[] Y0 = new byte[] {g0(inp[0], y1)};
			byte[] Y1 = new byte[] {y1};
			byte[] Y2 = new byte[] {y2};
			byte[] Y3 = new byte[] {g1(y2, inp[3])};
			
			byte[] left = concat(Y0, Y1);
			byte[] right = concat(Y2, Y3);
			byte[] full = concat(left, right);
			
			return full;
		}
	    
	    // To find xor for two byte arrays
	    public static byte[] xor(byte[] a, byte[] b) {
			if (a.length == b.length) {		
				int i = 0;
				byte[] output = new byte[a.length];
				for (byte n : a)
					output[i] = (byte) (n ^ b[i++]);
				
				return output;
			}
			
			return null;		
		}
	    
	    // convert byte array to their respective integer values similiar to unpack function provided in encryption code
	    public static int convertByteArrayToIntger(byte[] bytes) {
	        return ((bytes[0] & 0xFF) << 24) |
	                ((bytes[1] & 0xFF) << 16) |
	                ((bytes[2] & 0xFF) << 8) |
	                ((bytes[3] & 0xFF) << 0);
	    }
	    
	    public static byte[] hextobytearray(String str) {
	        byte[] val = new byte[str.length() / 2];
	        for (int i = 0; i < val.length; i++) {
	           int index = i * 2;
	           int j = Integer.parseInt(str.substring(index, index + 2), 16);
	           val[i] = (byte) j;
	        }
	        return(val);
	     }
	    
	    
	    
	    // try 1  out of the k1_prime equation with larger results
	  /*public static void phase1_k1(byte[] K0) throws Exception {
			read_file();
			stripdata();
			for (byte a0 = -128 ; a0 < 127 ; a0++) {
				for (byte a1 = -128 ; a1 < 127 ; a1++) 
				{	
					 
					int count0 = 0 ,count1 =0 ;
					for(int i =0 ; i<=199;i++)
					{   
	
						byte[] full_plaintext  = htob(plaintext.get(i));
						byte L0[] = Arrays.copyOfRange(full_plaintext, 0, 4);
						byte R0[] = Arrays.copyOfRange(full_plaintext, 4, 8);
						byte[] full_ciphertext  = htob(ciphertext.get(i));
						byte L4[] = Arrays.copyOfRange(full_ciphertext, 0, 4);
						byte R4[] = Arrays.copyOfRange(full_ciphertext, 4, 8);
						
						byte[] K1_prime = new byte[]{0, a0, a1, 0}; 
						byte[] xor_roundfunction_1 = xor(L0,R0);
						
						byte[] xor_rounffunction_final = F(xor( xor_roundfunction_1,K0));
						
						
						byte[] xor_1_1 = xor(L0,R0);
						byte[] xor_1_final = xor(xor_1_1,L4);
						
						byte[] xor_2_1 = xor(L0,L4);
						byte[] xor_2_final = xor(xor_2_1,R4);
						
						int bit_5 = (convertByteArrayToIntger(xor_1_final)>>26)&1;
						int bit_13 = (convertByteArrayToIntger(xor_1_final)>>18)&1;
						int bit_21 = (convertByteArrayToIntger(xor_1_final)>>10)&1;
						
						int bit_15_1 = (convertByteArrayToIntger(xor_rounffunction_final)>>16)&1;
						int bit_15_2 = (convertByteArrayToIntger(xor_2_final)>>16)&1;
						
						int k1_15 = (convertByteArrayToIntger(K1_prime)>>16)&1;
						
						int constant = (bit_5^bit_13^bit_21^bit_15_1^bit_15_2^k1_15);
						if(constant == 0)
						{
							count0 = count0+1;
							
						}
						else
						{
							count1 = count1+1;
							
							
						}
						if(count0 == 200) 
						{
							//System.out.println(count0);
							key1.add(btoh(K1_prime));
							//phase2_k1(a0,a1,K0);
						
						}
						else if(count1 ==200) 
						{
							//System.out.println(count1);
							key1.add(btoh(K1_prime));
							//phase2_k1(a0,a1,K0);
						}
						
					}
					
				}
			}
			} */
	    public static void phase2_k2(byte a0, byte a1, byte[] K0, byte[] K1) throws Exception {
			read_file();
			stripdata();
			//System.out.println(K0);
			for (byte b0 = -128 ; b0 < 127 ; b0++) {
				for (byte b1 = -128 ; b1 < 127 ; b1++) 
				{	
					 
					int count0 = 0 ,count1 =0 ;
					int count01 = 0, count11 =0 ;
					for(int i =0 ; i<=199;i++)
					{   
	
						byte[] full_plaintext  = htob(plaintext.get(i));
						byte L0[] = Arrays.copyOfRange(full_plaintext, 0, 4);
						byte R0[] = Arrays.copyOfRange(full_plaintext, 4, 8);
						byte[] full_ciphertext  = htob(ciphertext.get(i));
						byte L4[] = Arrays.copyOfRange(full_ciphertext, 0, 4);
						byte R4[] = Arrays.copyOfRange(full_ciphertext, 4, 8);
						
						byte[] K2 = new byte[] {b0, (byte) (a0^b0), (byte) (a1^b1), b1};
						
						byte[] xor_1_x1 = xor(R0,L0);
						byte[] xor_2_x1 = F(xor(xor_1_x1,K0));
						byte[] X1 = xor(xor_2_x1,L0);
						byte[] xor_x2_1 = F(xor(X1,K1));
						byte[] xor_x2_2 = xor(xor_x2_1,L0);
						byte[] X2 = xor(xor_x2_2,R0);
						
						
						
						//System.out.println(X1);
						
						byte[] xor_round_function = F(xor(X2,K2));
						
						
						
						byte[] xor_2_1 = xor(L4,X2);
					
						
						
						int bit_23 = (convertByteArrayToIntger(xor_2_1)>>8)&1;
						int bit_29 = (convertByteArrayToIntger(xor_2_1)>>2)&1;
						
						int bit_31_1 = (convertByteArrayToIntger(X1)>>0)&1;
						int bit_31_2 = (convertByteArrayToIntger(xor_round_function)>>0)&1;
						
						
						
						int constant = (bit_23^bit_29^bit_31_1^bit_31_2);
						//System.out.println(constant);
						if(constant == 0)
						{
							count0 = count0+1;
							
						}
						else
						{
							count1 = count1+1;
							
							
						}
						if(count0 == 200) 
						{
							//System.out.println(count0);
							key2_final1.add(btoh(K1));
							
						
						}
						else if(count1 ==200) 
						{
							//System.out.println(count1);
							key2_final1.add(btoh(K1));
							
						}
						
						//Equation try out
						int bit_5 = (convertByteArrayToIntger(xor_2_1)>>26)&1;
						int bit_15 = (convertByteArrayToIntger(xor_2_1)>>16)&1;
						
						int bit_7_1 = (convertByteArrayToIntger(X1)>>24)&1;
						int bit_7_2 = (convertByteArrayToIntger(xor_round_function)>>24)&1;
						
						
						int constant2 = (bit_5^bit_15^bit_7_1^bit_7_2);
						//System.out.println(constant);
						if(constant2 == 0)
						{
							count01 = count01+1;
							
						}
						else
						{
							count11 = count11+1;
							
							
						}
						if(count01 == 200) 
						{
							//System.out.println(count0);
							key2_final2.add(btoh(K1));
							
						
						}
						else if(count11 ==200) 
						{
							//System.out.println(count1);
							key2_final2.add(btoh(K1));
							
						}
						
					}
					
				}
			}
			}
	   
	  
	    
	    
	    public static void phase1_k2(byte[] K0,byte[] K1) throws Exception {
			read_file();
			stripdata();
			//System.out.println(K0);
			for (byte a0 = -128 ; a0 < 127 ; a0++) {
				for (byte a1 = -128 ; a1 < 127 ; a1++) 
				{	
					 
					int count0 = 0 ,count1 =0 ;
					for(int i =0 ; i<=199;i++)
					{   
	
						byte[] full_plaintext  = htob(plaintext.get(i));
						byte L0[] = Arrays.copyOfRange(full_plaintext, 0, 4);
						byte R0[] = Arrays.copyOfRange(full_plaintext, 4, 8);
						byte[] full_ciphertext  = htob(ciphertext.get(i));
						byte L4[] = Arrays.copyOfRange(full_ciphertext, 0, 4);
						byte R4[] = Arrays.copyOfRange(full_ciphertext, 4, 8);
						
						byte[] K2_prime = new byte[]{0, a0, a1, 0};
						
						byte[] xor_1_x1 = xor(R0,L0);
						byte[] xor_2_x1 = F(xor(xor_1_x1,K0));
						byte[] X1 = xor(xor_2_x1,L0);
						byte[] xor_x2_1 = F(xor(X1,K1));
						byte[] xor_x2_2 = xor(xor_x2_1,L0);
						byte[] X2 = xor(xor_x2_2,R0);
						
						
						
						//System.out.println(X1);
						
						byte[] xor_round_function = F(xor(X2,K2_prime));
						
						
						
						byte[] xor_2_1 = xor(L4,X2);
					
						
						int bit_5 = (convertByteArrayToIntger(xor_2_1)>>26)&1;
						int bit_13 = (convertByteArrayToIntger(xor_2_1)>>18)&1;
						int bit_21 = (convertByteArrayToIntger(xor_2_1)>>10)&1;
						
						int bit_15_1 = (convertByteArrayToIntger(X1)>>16)&1;
						int bit_15_2 = (convertByteArrayToIntger(xor_round_function)>>16)&1;
						
						
						int constant = (bit_5^bit_13^bit_21^bit_15_1^bit_15_2);
						//System.out.println(constant);
						if(constant == 0)
						{
							count0 = count0+1;
							
						}
						else
						{
							count1 = count1+1;
							
							
						}
						if(count0 == 200) 
						{
							//System.out.println(count0);
							key1.add(btoh(K2_prime));
							phase2_k2(a0,a1,K0,K1);
							
						
						}
						else if(count1 ==200) 
						{
							//System.out.println(count1);
							key1.add(btoh(K2_prime));
							phase2_k2(a0,a1,K0,K1);
							
						}
						
					}
					
				}
			}
			}
	    
	    
	    
	    
	    
	    
	    
	    
	    
	    public static void phase2_k1(byte a0, byte a1, byte[] K0) throws Exception {
			read_file();
			stripdata();
			//System.out.println(K0);
			for (byte b0 = -128 ; b0 < 127 ; b0++) {
				for (byte b1 = -128 ; b1 < 127 ; b1++) 
				{	
					 
					int count0 = 0 ,count1 =0 ;
					int count01 = 0, count11 =0 ;
					for(int i =0 ; i<=199;i++)
					{   
	
						byte[] full_plaintext  = htob(plaintext.get(i));
						byte L0[] = Arrays.copyOfRange(full_plaintext, 0, 4);
						byte R0[] = Arrays.copyOfRange(full_plaintext, 4, 8);
						byte[] full_ciphertext  = htob(ciphertext.get(i));
						byte L4[] = Arrays.copyOfRange(full_ciphertext, 0, 4);
						byte R4[] = Arrays.copyOfRange(full_ciphertext, 4, 8);
						
						byte[] K1 = new byte[] {b0, (byte) (a0^b0), (byte) (a1^b1), b1};
						
						byte[] xor_1_x1 = xor(R0,L0);
						byte[] xor_2_x1 = F(xor(xor_1_x1,K0));
						byte[] X1 = xor(xor_2_x1,L0);
						
						//System.out.println(X1);
						
						byte[] xor_round_function = F(xor(X1,K1));
						
						
						byte[] xor_1_1 = xor(L0,R0);
						
						byte[] xor_2_1 = xor(L4,R4);
						byte[] xor_2_final = xor(xor_2_1,X1);
						
						int bit_23 = (convertByteArrayToIntger(xor_2_final)>>8)&1;
						int bit_29 = (convertByteArrayToIntger(xor_2_final)>>2)&1;
						
						int bit_31_1 = (convertByteArrayToIntger(xor_1_1)>>0)&1;
						int bit_31_2 = (convertByteArrayToIntger(xor_round_function)>>0)&1;
						
						
						int constant = (bit_23^bit_29^bit_31_1^bit_31_2);
						//System.out.println(constant);
						if(constant == 0)
						{
							count0 = count0+1;
							
						}
						else
						{
							count1 = count1+1;
							
							
						}
						if(count0 == 200) 
						{
							//System.out.println(count0);
							key1_final1.add(btoh(K1));
							
						
						}
						else if(count1 ==200) 
						{
							//System.out.println(count1);
							key1_final1.add(btoh(K1));
							
						}
						
						//Equation try out
						int bit_5 = (convertByteArrayToIntger(xor_2_final)>>26)&1;
						int bit_15 = (convertByteArrayToIntger(xor_2_final)>>16)&1;
						
						int bit_7_1 = (convertByteArrayToIntger(xor_1_1)>>24)&1;
						int bit_7_2 = (convertByteArrayToIntger(xor_round_function)>>24)&1;
						
						
						int constant2 = (bit_5^bit_15^bit_7_1^bit_7_2);
						//System.out.println(constant);
						if(constant2 == 0)
						{
							count01 = count01+1;
							
						}
						else
						{
							count11 = count11+1;
							
							
						}
						if(count01 == 200) 
						{
							//System.out.println(count0);
							key1_final2.add(btoh(K1));
							
						
						}
						else if(count11 ==200) 
						{
							//System.out.println(count1);
							key1_final2.add(btoh(K1));
							
						}
						
					}
					
				}
			}
			}
	   
	  
						
				
	    
	    public static void phase1_k1(byte[] K0) throws Exception {
			read_file();
			stripdata();
			//System.out.println(K0);
			for (byte a0 = -128 ; a0 < 127 ; a0++) {
				for (byte a1 = -128 ; a1 < 127 ; a1++) 
				{	
					 
					int count0 = 0 ,count1 =0 ;
					for(int i =0 ; i<=199;i++)
					{   
	
						byte[] full_plaintext  = htob(plaintext.get(i));
						byte L0[] = Arrays.copyOfRange(full_plaintext, 0, 4);
						byte R0[] = Arrays.copyOfRange(full_plaintext, 4, 8);
						byte[] full_ciphertext  = htob(ciphertext.get(i));
						byte L4[] = Arrays.copyOfRange(full_ciphertext, 0, 4);
						byte R4[] = Arrays.copyOfRange(full_ciphertext, 4, 8);
						
						byte[] K1_prime = new byte[]{0, a0, a1, 0};
						
						byte[] xor_1_x1 = xor(R0,L0);
						byte[] xor_2_x1 = F(xor(xor_1_x1,K0));
						byte[] X1 = xor(xor_2_x1,L0);
						
						//System.out.println(X1);
						
						byte[] xor_round_function = F(xor(X1,K1_prime));
						
						
						byte[] xor_1_1 = xor(L0,R0);
						
						byte[] xor_2_1 = xor(L4,R4);
						byte[] xor_2_final = xor(xor_2_1,X1);
						
						int bit_5 = (convertByteArrayToIntger(xor_2_final)>>26)&1;
						int bit_13 = (convertByteArrayToIntger(xor_2_final)>>18)&1;
						int bit_21 = (convertByteArrayToIntger(xor_2_final)>>10)&1;
						
						int bit_15_1 = (convertByteArrayToIntger(xor_1_1)>>16)&1;
						int bit_15_2 = (convertByteArrayToIntger(xor_round_function)>>16)&1;
						
						
						int constant = (bit_5^bit_13^bit_21^bit_15_1^bit_15_2);
						//System.out.println(constant);
						if(constant == 0)
						{
							count0 = count0+1;
							
						}
						else
						{
							count1 = count1+1;
							
							
						}
						if(count0 == 200) 
						{
							//System.out.println(count0);
							key1.add(btoh(K1_prime));
							phase2_k1(a0,a1,K0);
						
						}
						else if(count1 ==200) 
						{
							//System.out.println(count1);
							key1.add(btoh(K1_prime));
							phase2_k1(a0,a1,K0);
						}
						
					}
					
				}
			}
			}
	    
	   
	    
	    
						
	    
	    // phase 2 for calculating final k0 values
	    public static void phase2(byte a0,byte a1) throws Exception
	    {
	    	for (byte b0 = -128 ; b0 < 127 ; b0++)  
			{
				for (byte b1 = -128 ; b1 < 127 ; b1++) 
				{ 
					int count0_1 = 0, count1_1 =0 ;
					int count0_11 = 0, count1_11 = 0;
					
					byte[] K = new byte[] {b0, (byte) (a0^b0), (byte) (a1^b1), b1}; // generating key for final K0
					for(int i =0 ; i<=199;i++)
					{   
						
						//Calculating the left and right halves
						//dividing the text into two halves first convert hex to binary and divide the text two two 32 bit(4 byte)parts
						byte[] full_plaintext  = htob(plaintext.get(i));
						byte L0[] = Arrays.copyOfRange(full_plaintext, 0, 4);
						byte R0[] = Arrays.copyOfRange(full_plaintext, 4, 8);
						byte[] full_ciphertext  = htob(ciphertext.get(i));
						byte L4[] = Arrays.copyOfRange(full_ciphertext, 0, 4);
						byte R4[] = Arrays.copyOfRange(full_ciphertext, 4, 8);
					
						
						// Getting all the required xor values
						byte[] xor_roundfunction_1 = xor(L0,R0); 
						byte[] xor_roundfunction_final = F(xor( xor_roundfunction_1,K));
						
						
						byte[] xor_1_1 = xor(L0,R0);
						byte[] xor_1_final = xor(xor_1_1,L4);
						
						byte[] xor_2_1 = xor(L0,L4);
						byte[] xor_2_final = xor(xor_2_1,R4);
						
						//Findings particular bits
						 //System.out.println("Byte Array (Hex) : " + convertByteArrayToInt2(xor_rounffunction_final));
						int bit_23 = (convertByteArrayToIntger(xor_1_final)>>8)&1;
						int bit_29 = (convertByteArrayToIntger(xor_1_final)>>2)&1;
						//int bit_21 = (convertByteArrayToInt2(xor_1_final)>>10)&1;
						
						int bit_31_1 = (convertByteArrayToIntger(xor_roundfunction_final)>>0)&1;
						int bit_31_2 = (convertByteArrayToIntger(xor_2_final)>>0)&1;
						
						//find constant
						int constant = (bit_23^bit_29^bit_31_1^bit_31_2);
						if(constant == 0)
						{
							count0_1 = count0_1+1;
							if(count0_1 == 200) 
							{
								key.add(btoh(K));
								//phase1_k1(K);
								//System.out.println(btoh(K));
							}
					
						}
						else 
						{
							 count1_1 = count1_1+1;
							 if(count1_1 == 200) 
								{
									key.add(btoh(K));
									//phase1_k1(K);
									//System.out.println(btoh(K));
								}
						}
						//System.out.println(constant);
						
						//testing another equation for K0 results and it produce 2040 results
						int bit_5 = (convertByteArrayToIntger(xor_1_final)>>26)&1;
						int bit_15 = (convertByteArrayToIntger(xor_1_final)>>16)&1;
						int bit_7_1 = (convertByteArrayToIntger(xor_2_final)>>24)&1;
						int bit_7_2 = (convertByteArrayToIntger(xor_roundfunction_final)>>24)&1;
						
						int constant2 = bit_5^bit_15^bit_7_1^bit_7_2;
						//System.out.println(constant2);
						if(constant2 == 0)
						{
							count0_11 = count0_11+1;
							if(count0_11 == 200) 
							{
								//System.out.println(count0_11);
								keyguess2.add(btoh(K));
								//System.out.println(btoh(K));
							}
					
						}
						else 
						{
							 count1_11 = count1_11+1;
							 if(count1_11 == 200) 
								{
								    //System.out.println(count1_11);
									keyguess2.add(btoh(K));
									//System.out.println(btoh(K));
								}
						}
						
						
					}
					
				}
			}

		}
	    
	 // phase 1 for calculating ko_prime  
	public static void main(String[] args) throws Exception {
		read_file();
		stripdata();
		System.out.println("Searching for K0 possible values.......");
		//byte[] plain = new byte[];
		for (byte a0 = -128 ; a0 < 127 ; a0++) { // loops for all possible 16 bit values 2^16 or 0x00-0xff = (a0,a1)
			for (byte a1 = -128 ; a1 < 127 ; a1++) 
			{
				int count0 = 0 ,count1 =0 ; // Initialize the counts 
				for(int i =0 ; i<=199;i++) // read all possible plain text and cipher text
				{   
					
					//Calculating the left and right halves
					//dividing the text into two halves first convert hex to binary and divide the text two two 32 bit(4 byte)parts
					byte[] full_plaintext  = htob(plaintext.get(i));
					byte L0[] = Arrays.copyOfRange(full_plaintext, 0, 4);
					byte R0[] = Arrays.copyOfRange(full_plaintext, 4, 8);
					byte[] full_ciphertext  = htob(ciphertext.get(i));
					byte L4[] = Arrays.copyOfRange(full_ciphertext, 0, 4);
					byte R4[] = Arrays.copyOfRange(full_ciphertext, 4, 8);
					
					byte[] K0_prime = new byte[]{0, a0, a1, 0}; //generate key with middle 16 bits
					
					// Getting all the required xor values
					byte[] xor_roundfunction_1 = xor(L0,R0); 
					byte[] xor_rounffunction_final = F(xor( xor_roundfunction_1,K0_prime));
					
					
					byte[] xor_1_1 = xor(L0,R0);
					byte[] xor_1_final = xor(xor_1_1,L4);
					
					byte[] xor_2_1 = xor(L0,L4);
					byte[] xor_2_final = xor(xor_2_1,R4);
					
					//Findings particular bits
					int bit_5 = (convertByteArrayToIntger(xor_1_final)>>26)&1;
					int bit_13 = (convertByteArrayToIntger(xor_1_final)>>18)&1;
					int bit_21 = (convertByteArrayToIntger(xor_1_final)>>10)&1;
					
					int bit_15_1 = (convertByteArrayToIntger(xor_rounffunction_final)>>16)&1;
					int bit_15_2 = (convertByteArrayToIntger(xor_2_final)>>16)&1;
					
					//find constant
					int constant = (bit_5^bit_13^bit_21^bit_15_1^bit_15_2);
					//System.out.println(constant);
					if(constant == 0)
					{
						count0 = count0+1;
						//if(count0 == 200) {
						//System.out.println(count0);}
						
					}
					else
					{
						count1 = count1+1;
						//System.out.println(count_1);
						
					}
					//System.out.println(constant);
					if(count0 == 200) 
					{
						//System.out.println(count0);
						phase2(a0,a1);
					
					}
					else if(count1 ==200) 
					{
						//System.out.println(count1);
						phase2(a0,a1);
					}
				}
				
			}
		}
		System.out.println("Results after K0 guess 1: " + key.size());
		System.out.println("Results after K0 guess 2 : " + keyguess2.size());
		
		//taking intersection of both k0 results to find common elements to narrow down results of K0
		key.retainAll(keyguess2);
		  
        // print list 1
        System.out.println("Common elements: "+ key.size());
        System.out.println("Common elements values in hex: "+ key);
        
        //K1 searching
        System.out.println("Searching for K1 possible values.......");
        for(int i = 0; i<=15; i++ ) {
        phase1_k1(hextobytearray(key.get(i)));
        
        }
        System.out.println("Results after K1_prime guess  : " + key1.size());
        System.out.println("Results after K1 guess 1  : " + key1_final1.size());
        System.out.println("Results after K1 guess 2  : " + key1_final2.size());
        
      //taking intersection of both k1 results to find common elements to narrow down results of K1
      		key1_final1.retainAll(key1_final2);
      		  
              // print list 1
              System.out.println("Common elements: "+ key1_final1.size());
              System.out.println("Common elements values in hex: "+ key1_final1);
              
            //K2 searching
              System.out.println("Searching for K2 possible values.......");
              for(int i = 0; i<=15; i++ ) {
            	  for(int j = 0; j<=63 ; j++){
               byte[] K0 = hextobytearray(key.get(i));
               byte[] K1 = hextobytearray(key1_final1.get(j));
               phase1_k2(K0,K1);
              
              }}
              System.out.println("Results after K2_prime guess  : " + key2.size());
              System.out.println("Results after K2 guess 1  : " + key2_final1.size());
              System.out.println("Results after K2 guess 2  : " + key2_final2.size());
              
              key2_final1.retainAll(key2_final2);
      		  
              // print list 1
              System.out.println("Common elements: "+ key2_final1.size());
              System.out.println("Common elements values in hex: "+ key2_final1);

	}
	
	
}
		
	



