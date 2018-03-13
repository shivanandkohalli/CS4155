import java.util.HashMap;
import java.util.Map;


public class Two_Trie {
	private TrieNode root;
	private static int searchCount = 0;
	
	public static int getSearchCount() {
		return Two_Trie.searchCount;
	}

	public Two_Trie()
	{
		// initialise the root with a TrieNode
		root = new TrieNode();
	}
	
	public void insertData(String s)
	{
		TrieNode presentNode = root;
		
		for (int i=0;i<s.length();i=i+2)
		{
			Map<String, TrieNode> presentChild = presentNode.getChild();
			
			String toInsert;
			if(i+1 < s.length())
				 toInsert = s.substring(i, i+2);
			else
				toInsert = s.substring(i,i+1);
			
			if(presentChild.containsKey(toInsert) == true)
			{
				presentNode = presentChild.get(toInsert);
			}
			else
			{
				presentNode = presentNode.addToChild(toInsert);
			}
		}
		
		presentNode.setMatch(true);
	}
	
	public boolean searchData(String s)
	{
		TrieNode presentNode = root;
		
		for (int i=0;i<s.length();i=i+2)
		{
			Two_Trie.searchCount++;
			Map<String, TrieNode> presentChild = presentNode.getChild();
			String c;
			if(i+1 < s.length())
				c = s.substring(i, i+2);
			else
				c = s.substring(i,i+1);
			
			if(presentChild.containsKey(c))
			{
				presentNode = presentChild.get(c);
			}
			else
			{
				return false;
			}
		}
		
		if(presentNode.isMatch() == true)
			return true;
		else
			return false;
	}
}
