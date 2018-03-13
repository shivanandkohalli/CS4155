import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

public class Main {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		Trie trie = new Trie();
		
		try (BufferedReader br = new BufferedReader(new FileReader("./src/block_ip.txt")))
		{
		    String line;
		    while ((line = br.readLine()) != null) {
		       String []parsed = line.split("\\s+");
		       parsed = parsed[0].split("/");
		       String block_ip = convertIPtoBitString(parsed[0],Integer.parseInt(parsed[1]));
		       trie.insertData(block_ip);
		    }
		}
		//System.out.println("Hello");
			catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		try (BufferedReader br = new BufferedReader(new FileReader("./src/input_ip.txt")))
		{
		    String line;
		    while ((line = br.readLine()) != null) {
		       String input_ip = convertIPtoBitString(line,32);
		       trie.searchData(input_ip);
		    }
		}
		//System.out.println("Hello");
			catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println(Trie.getSearchCount());
		
		
		
	}
	
	public static String convertIPtoBitString(String str, int length)
	{
		String []ip_split = str.split("\\.");
		
		for(int i=0;i<4;i++)
		{
			ip_split[i] = Integer.toBinaryString(Integer.parseInt(ip_split[i]));
			
			String pad = "";
			int len = 8-ip_split[i].length();
			for(int j=0;j < len;j++)
			{
				pad = pad + '0';
			}
			ip_split[i] = pad + ip_split[i];
		}
		String retval = ip_split[0] + ip_split[1] + ip_split[2] + ip_split[3];
		
		return retval.substring(0, length);
	}
	

}
